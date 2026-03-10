"""
🔐 Vault Bot - بوت التخزين الشخصي الآمن
==========================================
ميزات الأمان:
- كلمة مرور رئيسية مشفرة بـ SHA-256
- قفل تلقائي بعد 3 محاولات خاطئة
- إشعار فوري عند أي محاولة دخول مشبوهة
- تشفير أسماء الملفات بـ Fernet
- انتهاء الجلسة تلقائياً بعد 30 دقيقة
- قبو خاص برمز منفصل
- حماية كاملة: البوت يعمل فقط للمالك
"""

import os
import sqlite3
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, ConversationHandler, filters,
    ContextTypes
)

# ============================================================
#  ⚙️ الإعدادات — غيّر هذي القيم قبل تشغيل البوت
# ============================================================
TOKEN          = "ضع_توكن_البوت_هنا"
OWNER_ID       = 123456789          # ID تيليكرام الخاص فيك
MASTER_PASS    = "كلمة_المرور_الرئيسية"   # كلمة مرور الدخول
VAULT_PASS     = "رمز_القبو_الخاص"       # رمز القبو الخاص المشفر
MAX_ATTEMPTS   = 3                  # محاولات قبل الحجب
LOCK_MINUTES   = 10                 # مدة الحجب بالدقائق
SESSION_MINS   = 30                 # مدة الجلسة بالدقائق
# ============================================================

# ─── تشفير Fernet ───────────────────────────────────────────
KEY_FILE = "vault.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        _KEY = f.read()
else:
    _KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(_KEY)

fernet = Fernet(_KEY)

def enc(text: str) -> str:
    return fernet.encrypt(text.encode()).decode()

def dec(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        return "???"

def hash_pass(pw: str) -> str:
    return hashlib.sha256(f"vaultbot_salt_2025_{pw}".encode()).hexdigest()

# ─── قاعدة البيانات ─────────────────────────────────────────
def init_db():
    con = sqlite3.connect("vault.db")
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS files (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tg_file_id      TEXT    NOT NULL,
            file_type       TEXT    NOT NULL,
            enc_name        TEXT,
            folder          TEXT    DEFAULT 'عام',
            caption         TEXT    DEFAULT '',
            added_at        TEXT
        );
        CREATE TABLE IF NOT EXISTS folders (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    UNIQUE NOT NULL,
            created_at      TEXT,
            is_vault        INTEGER DEFAULT 0,
            vault_pass_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS security (
            id              INTEGER PRIMARY KEY,
            failed          INTEGER DEFAULT 0,
            locked_until    TEXT
        );
    """)
    cur.execute("INSERT OR IGNORE INTO security (id, failed) VALUES (1, 0)")
    # المجلدات الافتراضية
    defaults = [
        ("📸 صور",        0, None),
        ("🎥 فيديوهات",   0, None),
        ("📄 مستندات",    0, None),
        ("📝 ملاحظات",    0, None),
        ("🔐 خاص",        1, hash_pass(VAULT_PASS)),
    ]
    for name, is_vault, vph in defaults:
        cur.execute(
            "INSERT OR IGNORE INTO folders (name, created_at, is_vault, vault_pass_hash) VALUES (?,?,?,?)",
            (name, _now(), is_vault, vph)
        )
    con.commit()
    con.close()

def _now():
    return datetime.now().isoformat(timespec="seconds")

# ─── الجلسات ────────────────────────────────────────────────
_sessions: dict = {}

def sess(uid):
    if uid not in _sessions:
        _sessions[uid] = {"auth": False, "active": None, "vault": False, "folder": None}
    return _sessions[uid]

def is_auth(uid):
    s = sess(uid)
    if not s["auth"]:
        return False
    if s["active"] and (datetime.now() - s["active"]).seconds / 60 > SESSION_MINS:
        s["auth"] = s["vault"] = False
        return False
    return True

def touch(uid):
    sess(uid)["active"] = datetime.now()

# ─── الأمان ─────────────────────────────────────────────────
def is_locked():
    row = sqlite3.connect("vault.db").execute(
        "SELECT failed, locked_until FROM security WHERE id=1").fetchone()
    if row and row[1]:
        until = datetime.fromisoformat(row[1])
        if datetime.now() < until:
            return True, int((until - datetime.now()).seconds / 60) + 1
    return False, 0

def inc_failed():
    con = sqlite3.connect("vault.db")
    con.execute("UPDATE security SET failed=failed+1 WHERE id=1")
    n = con.execute("SELECT failed FROM security WHERE id=1").fetchone()[0]
    if n >= MAX_ATTEMPTS:
        until = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat()
        con.execute("UPDATE security SET locked_until=?, failed=0 WHERE id=1", (until,))
    con.commit(); con.close()
    return n

def reset_failed():
    con = sqlite3.connect("vault.db")
    con.execute("UPDATE security SET failed=0, locked_until=NULL WHERE id=1")
    con.commit(); con.close()

# ─── States ─────────────────────────────────────────────────
(S_PASS, S_MAIN, S_FOLDERS, S_UPLOAD,
 S_SEARCH, S_VIEW, S_VAULT_PASS,
 S_NEW_FOLDER, S_RENAME) = range(9)

# ─── Keyboards ──────────────────────────────────────────────
def kb_main():
    return InlineKeyboardMarkup([
        [btn("📁 مجلداتي",   "folders"),    btn("➕ مجلد جديد", "new_folder")],
        [btn("🔍 بحث",       "search"),     btn("📊 إحصائيات",  "stats")],
        [btn("🔐 القبو الخاص","vault"),     btn("⚙️ الإعدادات", "settings")],
        [btn("🔒 قفل البوت", "lock")],
    ])

def kb_folders(show_vault=False):
    con = sqlite3.connect("vault.db")
    rows = con.execute(
        "SELECT name,is_vault FROM folders ORDER BY id").fetchall()
    con.close()
    btns, row = [], []
    for name, iv in rows:
        if iv and not show_vault:
            continue
        row.append(btn(name, f"folder:{name}"))
        if len(row) == 2:
            btns.append(row); row = []
    if row:
        btns.append(row)
    btns.append([btn("🔙 رجوع", "main")])
    return InlineKeyboardMarkup(btns)

def kb_folder_actions(name):
    return InlineKeyboardMarkup([
        [btn("📤 رفع ملف",    f"upload:{name}"),     btn("👁 عرض الملفات", f"list:{name}")],
        [btn("✏️ تغيير الاسم", f"rename:{name}"),    btn("🗑 حذف المجلد",  f"del_folder:{name}")],
        [btn("🔙 رجوع",       "folders")],
    ])

def btn(text, data):
    return InlineKeyboardButton(text, callback_data=data)

TYPE_EMOJI = {"photo":"🖼️","video":"🎬","document":"📄","text":"📝","audio":"🎵"}

# ─── Handlers ───────────────────────────────────────────────
async def cmd_start(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = upd.effective_user.id

    # حماية: أي شخص ثاني يحاول يدخل
    if uid != OWNER_ID:
        await upd.message.reply_text("⛔ غير مصرح لك بالدخول.")
        await ctx.bot.send_message(
            OWNER_ID,
            f"🚨 *تحذير!* شخص حاول يدخل البوت\n"
            f"👤 الاسم: {upd.effective_user.full_name}\n"
            f"🆔 ID: `{uid}`\n"
            f"⏰ الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            parse_mode="Markdown"
        )
        return ConversationHandler.END

    locked, mins = is_locked()
    if locked:
        await upd.message.reply_text(f"🔒 البوت محجوب لمدة {mins} دقيقة بسبب محاولات خاطئة.")
        return S_PASS

    if is_auth(uid):
        touch(uid)
        await upd.message.reply_text("✅ أنت داخل بالفعل!", reply_markup=kb_main())
        return S_MAIN

    await upd.message.reply_text(
        "🔐 *القبو الشخصي الآمن*\n\nأكتب كلمة المرور للدخول:",
        parse_mode="Markdown"
    )
    return S_PASS


async def check_pass(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = upd.effective_user.id
    if uid != OWNER_ID:
        return ConversationHandler.END

    locked, mins = is_locked()
    if locked:
        await upd.message.reply_text(f"🔒 البوت محجوب لمدة {mins} دقيقة.")
        return S_PASS

    pw = upd.message.text.strip()
    try:
        await upd.message.delete()  # حذف الرسالة فيها كلمة المرور فوراً
    except Exception:
        pass

    if hash_pass(pw) == hash_pass(MASTER_PASS):
        reset_failed()
        _sessions[uid] = {"auth": True, "active": datetime.now(), "vault": False, "folder": None}
        await upd.message.reply_text(
            "✅ *أهلاً بك! تم الدخول بنجاح* 🗄️",
            parse_mode="Markdown",
            reply_markup=kb_main()
        )
        return S_MAIN
    else:
        n = inc_failed()
        left = MAX_ATTEMPTS - n
        if left <= 0:
            t = datetime.now().strftime("%H:%M:%S")
            await upd.message.reply_text(
                f"🚫 *تم حجب البوت لمدة {LOCK_MINUTES} دقيقة!*",
                parse_mode="Markdown"
            )
            await ctx.bot.send_message(
                OWNER_ID,
                f"🚨 *تحذير أمني!*\nتم حجب البوت بعد {MAX_ATTEMPTS} محاولات فاشلة\n⏰ {t}",
                parse_mode="Markdown"
            )
        else:
            await upd.message.reply_text(f"❌ كلمة مرور خاطئة! متبقي {left} محاولة.")
        return S_PASS


async def on_button(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = upd.callback_query
    uid = q.from_user.id

    if uid != OWNER_ID:
        await q.answer("⛔ غير مصرح"); return
    if not is_auth(uid):
        await q.message.edit_text("⏰ انتهت الجلسة. أرسل /start")
        return S_PASS

    touch(uid)
    d = q.data
    await q.answer()

    # ── القائمة الرئيسية ──────────────────────────────────
    if d == "main":
        await q.message.edit_text("🗄️ *القائمة الرئيسية*", parse_mode="Markdown", reply_markup=kb_main())
        return S_MAIN

    elif d == "folders":
        await q.message.edit_text("📁 *مجلداتك:*", parse_mode="Markdown", reply_markup=kb_folders())
        return S_FOLDERS

    elif d == "new_folder":
        await q.message.edit_text("📁 أكتب اسم المجلد الجديد:\n_(أو /cancel للإلغاء)_", parse_mode="Markdown")
        return S_NEW_FOLDER

    elif d.startswith("folder:"):
        name = d.split(":",1)[1]
        sess(uid)["folder"] = name
        con = sqlite3.connect("vault.db")
        count = con.execute("SELECT COUNT(*) FROM files WHERE folder=?", (name,)).fetchone()[0]
        con.close()
        await q.message.edit_text(
            f"📁 *{name}*\n📎 عدد الملفات: {count}",
            parse_mode="Markdown",
            reply_markup=kb_folder_actions(name)
        )
        return S_FOLDERS

    elif d.startswith("upload:"):
        name = d.split(":",1)[1]
        sess(uid)["folder"] = name
        await q.message.edit_text(
            f"📤 أرسل أي ملف/صورة/فيديو/نص وسيُحفظ في *{name}*\n\nأرسل /done عند الانتهاء.",
            parse_mode="Markdown"
        )
        return S_UPLOAD

    elif d.startswith("list:"):
        name = d.split(":",1)[1]
        return await show_files(q, ctx, name)

    elif d.startswith("get:"):
        fid = int(d.split(":")[1])
        await send_file(ctx, uid, fid)
        return S_VIEW

    elif d.startswith("delete:"):
        fid = int(d.split(":")[1])
        kb = InlineKeyboardMarkup([[
            btn("✅ نعم احذفه", f"confirm_del:{fid}"),
            btn("❌ إلغاء",     "cancel_del")
        ]])
        await q.message.reply_text("🗑 تأكيد الحذف؟", reply_markup=kb)
        return S_VIEW

    elif d.startswith("confirm_del:"):
        fid = int(d.split(":")[1])
        con = sqlite3.connect("vault.db")
        folder = con.execute("SELECT folder FROM files WHERE id=?", (fid,)).fetchone()
        con.execute("DELETE FROM files WHERE id=?", (fid,))
        con.commit(); con.close()
        try: await q.message.delete()
        except Exception: pass
        if folder:
            await show_files(q, ctx, folder[0])
        return S_VIEW

    elif d == "cancel_del":
        try: await q.message.delete()
        except Exception: pass
        return S_VIEW

    elif d.startswith("del_folder:"):
        name = d.split(":",1)[1]
        kb = InlineKeyboardMarkup([[
            btn("✅ نعم احذف الكل", f"confirm_del_folder:{name}"),
            btn("❌ إلغاء",         f"folder:{name}")
        ]])
        await q.message.edit_text(
            f"⚠️ هل تريد حذف *{name}* وكل ملفاته؟ لا يمكن التراجع!",
            parse_mode="Markdown",
            reply_markup=kb
        )
        return S_FOLDERS

    elif d.startswith("confirm_del_folder:"):
        name = d.split(":",1)[1]
        con = sqlite3.connect("vault.db")
        con.execute("DELETE FROM files WHERE folder=?", (name,))
        con.execute("DELETE FROM folders WHERE name=?", (name,))
        con.commit(); con.close()
        await q.message.edit_text(
            f"✅ تم حذف *{name}*.", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[btn("🔙 رجوع", "folders")]])
        )
        return S_MAIN

    elif d.startswith("rename:"):
        name = d.split(":",1)[1]
        ctx.user_data["rename"] = name
        await q.message.edit_text(f"✏️ أكتب الاسم الجديد لـ *{name}*:", parse_mode="Markdown")
        return S_RENAME

    elif d == "search":
        await q.message.edit_text("🔍 أكتب اسم الملف الذي تبحث عنه:")
        return S_SEARCH

    elif d == "stats":
        con = sqlite3.connect("vault.db")
        total   = con.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        folders = con.execute("SELECT COUNT(*) FROM folders").fetchone()[0]
        by_type = con.execute("SELECT file_type, COUNT(*) FROM files GROUP BY file_type").fetchall()
        con.close()
        names = {"photo":"صور 🖼️","video":"فيديوهات 🎬","document":"مستندات 📄","text":"ملاحظات 📝","audio":"صوتيات 🎵"}
        txt = f"📊 *إحصائيات القبو:*\n\n📁 المجلدات: {folders}\n📎 إجمالي الملفات: {total}\n\n"
        for ft, c in by_type:
            txt += f"• {names.get(ft,ft)}: {c}\n"
        await q.message.edit_text(txt, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[btn("🔙 رجوع","main")]]))
        return S_MAIN

    elif d == "vault":
        if sess(uid)["vault"]:
            await q.message.edit_text("🔐 *القبو الخاص* — مفتوح", parse_mode="Markdown",
                reply_markup=kb_folder_actions("🔐 خاص"))
            return S_FOLDERS
        else:
            await q.message.edit_text("🔐 أكتب رمز القبو الخاص:")
            return S_VAULT_PASS

    elif d == "settings":
        txt = (
            "⚙️ *الإعدادات الحالية:*\n\n"
            f"• الجلسة تنتهي بعد: {SESSION_MINS} دقيقة\n"
            f"• الحجب بعد: {MAX_ATTEMPTS} محاولات خاطئة\n"
            f"• مدة الحجب: {LOCK_MINUTES} دقيقة\n\n"
            "_لتغيير هذه القيم عدّل الكود مباشرة في قسم الإعدادات أعلاه._"
        )
        await q.message.edit_text(txt, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[btn("🔙 رجوع","main")]]))
        return S_MAIN

    elif d == "lock":
        _sessions[uid] = {"auth":False,"active":None,"vault":False,"folder":None}
        await q.message.edit_text("🔒 تم قفل البوت. إلى اللقاء!")
        return ConversationHandler.END


async def show_files(q, ctx, folder_name: str):
    con = sqlite3.connect("vault.db")
    rows = con.execute(
        "SELECT id, file_type, enc_name FROM files WHERE folder=? ORDER BY added_at DESC",
        (folder_name,)
    ).fetchall()
    con.close()

    if not rows:
        await q.message.edit_text(
            f"📭 المجلد *{folder_name}* فارغ.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[btn("🔙 رجوع", f"folder:{folder_name}")]]))
        return S_FOLDERS

    kbs = []
    for fid, ftype, enc_name in rows:
        name = dec(enc_name) if enc_name else f"{ftype}_{fid}"
        em = TYPE_EMOJI.get(ftype, "📎")
        short = (name[:22] + "…") if len(name) > 22 else name
        kbs.append([btn(f"{em} {short}", f"get:{fid}"), btn("🗑", f"delete:{fid}")])
    kbs.append([btn("🔙 رجوع", f"folder:{folder_name}")])
    await q.message.edit_text(
        f"📁 *{folder_name}* — {len(rows)} ملف:",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(kbs)
    )
    return S_VIEW


async def send_file(ctx, uid: int, fid: int):
    con = sqlite3.connect("vault.db")
    row = con.execute("SELECT tg_file_id, file_type, caption FROM files WHERE id=?", (fid,)).fetchone()
    con.close()
    if not row:
        return
    tg_id, ftype, cap = row
    try:
        if   ftype == "photo":    await ctx.bot.send_photo   (uid, tg_id, caption=cap)
        elif ftype == "video":    await ctx.bot.send_video   (uid, tg_id, caption=cap)
        elif ftype == "audio":    await ctx.bot.send_audio   (uid, tg_id, caption=cap)
        elif ftype == "text":     await ctx.bot.send_message (uid, f"📝 {dec(tg_id)}")
        else:                     await ctx.bot.send_document(uid, tg_id, caption=cap)
    except Exception as e:
        await ctx.bot.send_message(uid, f"❌ خطأ في إرسال الملف: {e}")


async def handle_vault_pass(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = upd.effective_user.id
    pw  = upd.message.text.strip()
    try: await upd.message.delete()
    except Exception: pass

    if hash_pass(pw) == hash_pass(VAULT_PASS):
        sess(uid)["vault"] = True
        await upd.message.reply_text(
            "✅ *تم فتح القبو الخاص!* 🔓",
            parse_mode="Markdown",
            reply_markup=kb_folder_actions("🔐 خاص")
        )
        return S_FOLDERS
    else:
        await upd.message.reply_text(
            "❌ رمز خاطئ!",
            reply_markup=InlineKeyboardMarkup([[btn("🔙 رجوع","main")]]))
        return S_MAIN


async def handle_new_folder(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    name = upd.message.text.strip()
    con  = sqlite3.connect("vault.db")
    try:
        con.execute("INSERT INTO folders (name, created_at) VALUES (?,?)", (name, _now()))
        con.commit()
        await upd.message.reply_text(f"✅ تم إنشاء مجلد *{name}*!", parse_mode="Markdown", reply_markup=kb_main())
    except sqlite3.IntegrityError:
        await upd.message.reply_text("❌ هذا الاسم موجود بالفعل!", reply_markup=kb_main())
    finally:
        con.close()
    return S_MAIN


async def handle_rename(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    new  = upd.message.text.strip()
    old  = ctx.user_data.get("rename")
    if old:
        con = sqlite3.connect("vault.db")
        con.execute("UPDATE folders SET name=? WHERE name=?", (new, old))
        con.execute("UPDATE files    SET folder=? WHERE folder=?", (new, old))
        con.commit(); con.close()
    await upd.message.reply_text(f"✅ تم تغيير الاسم إلى *{new}*", parse_mode="Markdown", reply_markup=kb_main())
    return S_MAIN


async def handle_upload(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid    = upd.effective_user.id
    folder = sess(uid).get("folder", "عام")

    if upd.message.text and upd.message.text.startswith("/done"):
        await upd.message.reply_text("✅ تم! العودة للقائمة.", reply_markup=kb_main())
        return S_MAIN

    con, cur = sqlite3.connect("vault.db"), None
    cur = con.cursor()
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")

    if upd.message.photo:
        fid = upd.message.photo[-1].file_id
        cur.execute("INSERT INTO files VALUES (NULL,?,?,?,?,?,?)",
            (fid,"photo",enc(f"photo_{ts}.jpg"),folder,upd.message.caption or "",_now()))
        await upd.message.reply_text(f"✅ صورة محفوظة في *{folder}*", parse_mode="Markdown")

    elif upd.message.video:
        fid  = upd.message.video.file_id
        name = upd.message.video.file_name or f"video_{ts}.mp4"
        cur.execute("INSERT INTO files VALUES (NULL,?,?,?,?,?,?)",
            (fid,"video",enc(name),folder,upd.message.caption or "",_now()))
        await upd.message.reply_text(f"✅ فيديو محفوظ في *{folder}*", parse_mode="Markdown")

    elif upd.message.document:
        fid  = upd.message.document.file_id
        name = upd.message.document.file_name or f"doc_{ts}"
        cur.execute("INSERT INTO files VALUES (NULL,?,?,?,?,?,?)",
            (fid,"document",enc(name),folder,upd.message.caption or "",_now()))
        await upd.message.reply_text(f"✅ ملف محفوظ في *{folder}*", parse_mode="Markdown")

    elif upd.message.audio or upd.message.voice:
        fid = (upd.message.audio or upd.message.voice).file_id
        cur.execute("INSERT INTO files VALUES (NULL,?,?,?,?,?,?)",
            (fid,"audio",enc(f"audio_{ts}"),folder,"",_now()))
        await upd.message.reply_text(f"✅ صوت محفوظ في *{folder}*", parse_mode="Markdown")

    elif upd.message.text:
        txt = upd.message.text
        cur.execute("INSERT INTO files VALUES (NULL,?,?,?,?,?,?)",
            (enc(txt),"text",enc(f"note_{ts}"),folder,"",_now()))
        await upd.message.reply_text(f"✅ ملاحظة محفوظة في *{folder}*", parse_mode="Markdown")

    else:
        await upd.message.reply_text("⚠️ نوع ملف غير مدعوم.")

    con.commit(); con.close()
    return S_UPLOAD


async def handle_search(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if upd.message.text.startswith("/"):
        await upd.message.reply_text("❌ إلغاء.", reply_markup=kb_main())
        return S_MAIN

    q    = upd.message.text.strip().lower()
    con  = sqlite3.connect("vault.db")
    rows = con.execute("SELECT id, file_type, enc_name, folder FROM files").fetchall()
    con.close()

    results = [(fid,ft,dec(en),fo) for fid,ft,en,fo in rows if q in dec(en).lower()]

    if not results:
        await upd.message.reply_text(
            f"🔍 لا توجد نتائج لـ «{q}»",
            reply_markup=InlineKeyboardMarkup([[btn("🔙 رجوع","main")]]))
        return S_MAIN

    kbs = []
    for fid, ft, name, folder in results[:20]:
        em    = TYPE_EMOJI.get(ft,"📎")
        short = (name[:20]+"…") if len(name)>20 else name
        kbs.append([btn(f"{em} {short}  ({folder})", f"get:{fid}")])
    kbs.append([btn("🔙 رجوع","main")])
    await upd.message.reply_text(
        f"🔍 *{len(results)} نتيجة* لـ «{q}»:", parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(kbs))
    return S_VIEW


async def cmd_cancel(upd: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await upd.message.reply_text("❌ إلغاء.", reply_markup=kb_main())
    return S_MAIN


# ─── Main ────────────────────────────────────────────────────
def main():
    init_db()
    app = ApplicationBuilder().token(TOKEN).build()

    conv = ConversationHandler(
        entry_points=[CommandHandler("start", cmd_start)],
        states={
            S_PASS:       [MessageHandler(filters.TEXT & ~filters.COMMAND, check_pass)],
            S_MAIN:       [CallbackQueryHandler(on_button), CommandHandler("start", cmd_start)],
            S_FOLDERS:    [CallbackQueryHandler(on_button)],
            S_VIEW:       [CallbackQueryHandler(on_button)],
            S_UPLOAD:     [
                MessageHandler(filters.ALL & ~filters.COMMAND, handle_upload),
                CommandHandler("done",   lambda u,c: handle_upload(u,c)),
                CommandHandler("cancel", cmd_cancel),
            ],
            S_SEARCH:     [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_search),
                CommandHandler("cancel", cmd_cancel),
            ],
            S_VAULT_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_vault_pass)],
            S_NEW_FOLDER: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_new_folder),
                CommandHandler("cancel", cmd_cancel),
            ],
            S_RENAME:     [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_rename),
                CommandHandler("cancel", cmd_cancel),
            ],
        },
        fallbacks=[CommandHandler("start", cmd_start), CommandHandler("cancel", cmd_cancel)],
        allow_reentry=True,
    )

    app.add_handler(conv)
    print("🤖 البوت شغال...")
    app.run_polling()

if __name__ == "__main__":
    main()
