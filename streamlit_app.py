import io
import os
import calendar
import secrets
import hashlib
from datetime import datetime, date
from zoneinfo import ZoneInfo

import pandas as pd
import psycopg2
import psycopg2.extras
import streamlit as st
from PIL import Image, ImageOps

FMT = "%Y-%m-%d %H:%M:%S"
HODINOVA, METROVA = "hodinová", "metrová"
TZ = ZoneInfo("Europe/Prague")

st.set_page_config(page_title="Docházka", page_icon="🏗️", layout="centered")


def now():
    return datetime.now(TZ).replace(tzinfo=None)


def nn(x):
    """NaN -> None, aby se do databáze neuložilo 'NaN'."""
    if x is None:
        return None
    try:
        if pd.isna(x):
            return None
    except (TypeError, ValueError):
        pass
    return x


CZ_DNY = ["po", "út", "st", "čt", "pá", "so", "ne"]


def zmensi_foto(soubor):
    """Zmenší fotku (max 1280 px, JPEG), aby zabírala ~150 kB místo několika MB."""
    img = Image.open(soubor)
    img = ImageOps.exif_transpose(img).convert("RGB")
    img.thumbnail((1280, 1280))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=70, optimize=True)
    return buf.getvalue()


# ---------- databáze (Supabase / PostgreSQL) ----------
def db_url():
    try:
        return st.secrets["DATABASE_URL"]
    except Exception:
        return os.environ.get("DATABASE_URL", "")


def connect():
    url = db_url()
    if not url:
        st.error("Chybí nastavení DATABASE_URL (viz návod).")
        st.stop()
    return psycopg2.connect(url, sslmode="require", connect_timeout=10)


def run(sql, params=()):
    c = connect()
    try:
        with c:
            with c.cursor() as cur:
                cur.execute(sql, params)
    finally:
        c.close()


def run_many(stmts):
    c = connect()
    try:
        with c:
            with c.cursor() as cur:
                for sql, params in stmts:
                    cur.execute(sql, params)
    finally:
        c.close()


def one(sql, params=()):
    c = connect()
    try:
        with c:
            with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                r = cur.fetchone()
                return dict(r) if r else None
    finally:
        c.close()


def q(sql, params=()):
    c = connect()
    try:
        with c:
            with c.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
        return pd.DataFrame(rows, columns=cols)
    finally:
        c.close()


@st.cache_resource
def init_db():
    run(
        """
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            jmeno TEXT UNIQUE NOT NULL,
            heslo_hash TEXT NOT NULL,
            sul TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'zamestnanec',
            aktivni INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS zakazky(
            id SERIAL PRIMARY KEY,
            nazev TEXT UNIQUE NOT NULL,
            klient TEXT,
            typ_sazby TEXT NOT NULL,
            sazba DOUBLE PRECISION NOT NULL DEFAULT 0,
            aktivni INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS prirazeni(
            user_id INTEGER NOT NULL,
            zakazka_id INTEGER NOT NULL,
            sazba DOUBLE PRECISION,
            PRIMARY KEY(user_id, zakazka_id)
        );
        CREATE TABLE IF NOT EXISTS dochazka(
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            zakazka_id INTEGER NOT NULL,
            datum TEXT NOT NULL,
            prichod TEXT,
            odchod TEXT,
            hodiny DOUBLE PRECISION,
            metry DOUBLE PRECISION,
            poznamka TEXT,
            schvaleno INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS fotky(
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            zakazka_id INTEGER NOT NULL,
            datum TEXT NOT NULL,
            popis TEXT,
            data BYTEA NOT NULL
        );
        """
    )
    return True


# ---------- hesla ----------
def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()


def create_user(jmeno, heslo, role):
    salt = secrets.token_hex(16)
    run(
        "INSERT INTO users(jmeno, heslo_hash, sul, role) VALUES(%s,%s,%s,%s)",
        (jmeno.strip(), hash_pw(heslo, salt), salt, role),
    )


def set_password(user_id, heslo):
    salt = secrets.token_hex(16)
    run("UPDATE users SET heslo_hash=%s, sul=%s WHERE id=%s", (hash_pw(heslo, salt), salt, int(user_id)))


def login(jmeno, heslo):
    u = one("SELECT * FROM users WHERE jmeno=%s AND aktivni=1", (jmeno.strip(),))
    if u and secrets.compare_digest(u["heslo_hash"], hash_pw(heslo, u["sul"])):
        return u
    return None


# ---------- přihlášení ----------
def page_login():
    st.title("🏗️ Docházka")
    n = one("SELECT COUNT(*) AS n FROM users")["n"]

    if n == 0:
        st.info("První spuštění: vytvoř účet majitele (admina).")
        with st.form("setup"):
            j = st.text_input("Jméno admina")
            h1 = st.text_input("Heslo", type="password")
            h2 = st.text_input("Heslo znovu", type="password")
            if st.form_submit_button("Vytvořit"):
                if not j or len(h1) < 6:
                    st.error("Zadej jméno a heslo (min. 6 znaků).")
                elif h1 != h2:
                    st.error("Hesla se neshodují.")
                else:
                    create_user(j, h1, "admin")
                    st.success("Hotovo, teď se přihlas.")
                    st.rerun()
        return

    with st.form("login"):
        j = st.text_input("Jméno")
        h = st.text_input("Heslo", type="password")
        if st.form_submit_button("Přihlásit", use_container_width=True):
            u = login(j, h)
            if u:
                st.session_state.user = u
                st.rerun()
            else:
                st.error("Špatné jméno nebo heslo.")


# ---------- zaměstnanec ----------
def moje_zakazky(uid):
    return q(
        """SELECT z.id, z.nazev, z.typ_sazby FROM zakazky z
           JOIN prirazeni p ON p.zakazka_id=z.id
           WHERE p.user_id=%s AND z.aktivni=1 ORDER BY z.nazev""",
        (uid,),
    )


def page_zamestnanec(user):
    uid = user["id"]
    zak = moje_zakazky(uid)

    tab1, tab2, tab3, tab4 = st.tabs(["⏱️ Dnes", "✍️ Ruční zápis", "📋 Moje záznamy", "📷 Fotky"])

    with tab1:
        otevreny = one(
            """SELECT d.*, z.nazev, z.typ_sazby FROM dochazka d
               JOIN zakazky z ON z.id=d.zakazka_id
               WHERE d.user_id=%s AND d.odchod IS NULL AND d.prichod IS NOT NULL
               ORDER BY d.id DESC LIMIT 1""",
            (uid,),
        )

        if otevreny:
            start = datetime.strptime(otevreny["prichod"], FMT)
            st.success(f"Jsi na zakázce **{otevreny['nazev']}** od {start:%H:%M}")
            with st.form("odchod"):
                metry = 0.0
                if otevreny["typ_sazby"] == METROVA:
                    metry = st.number_input("Kolik metrů jsi udělal/a?", min_value=0.0, step=0.5)
                poz = st.text_input("Poznámka (nepovinné)")
                if st.form_submit_button("🔴 ODCHOD", use_container_width=True):
                    konec = now()
                    hodiny = round((konec - start).total_seconds() / 3600, 2)
                    run(
                        "UPDATE dochazka SET odchod=%s, hodiny=%s, metry=%s, poznamka=%s WHERE id=%s",
                        (konec.strftime(FMT), hodiny, float(metry), poz, int(otevreny["id"])),
                    )
                    st.rerun()
        else:
            if zak.empty:
                st.warning("Nemáš přiřazenou žádnou zakázku. Požádej majitele.")
            else:
                nazev = st.selectbox("Zakázka", zak["nazev"], key="prichod_zak")
                if st.button("🟢 PŘÍCHOD", use_container_width=True):
                    zid = int(zak.loc[zak["nazev"] == nazev, "id"].iloc[0])
                    t = now()
                    run(
                        "INSERT INTO dochazka(user_id, zakazka_id, datum, prichod) VALUES(%s,%s,%s,%s)",
                        (uid, zid, t.strftime("%Y-%m-%d"), t.strftime(FMT)),
                    )
                    st.rerun()

    with tab2:
        st.caption("Když jsi zapomněl/a dát příchod/odchod, nebo zapisuješ zpětně.")
        if zak.empty:
            st.warning("Nemáš přiřazenou žádnou zakázku.")
        else:
            with st.form("rucni"):
                nazev = st.selectbox("Zakázka", zak["nazev"])
                den = st.date_input("Datum", value=now().date())
                hodiny = st.number_input("Odpracované hodiny", min_value=0.0, max_value=24.0, step=0.25)
                metry = st.number_input("Metry (jen u metrové sazby)", min_value=0.0, step=0.5)
                poz = st.text_input("Poznámka")
                if st.form_submit_button("Uložit", use_container_width=True):
                    row = zak[zak["nazev"] == nazev].iloc[0]
                    if row["typ_sazby"] == HODINOVA and hodiny <= 0:
                        st.error("Zadej hodiny.")
                    elif row["typ_sazby"] == METROVA and metry <= 0:
                        st.error("U metrové zakázky zadej metry.")
                    else:
                        run(
                            """INSERT INTO dochazka(user_id, zakazka_id, datum, hodiny, metry, poznamka)
                               VALUES(%s,%s,%s,%s,%s,%s)""",
                            (uid, int(row["id"]), str(den), float(hodiny), float(metry), poz),
                        )
                        st.success("Uloženo.")

    with tab3:
        df = q(
            """SELECT d.id, d.datum AS "Datum", z.nazev AS "Zakázka", d.hodiny AS "Hodiny",
                      d.metry AS "Metry", d.schvaleno AS "Schváleno", d.poznamka AS "Poznámka"
               FROM dochazka d JOIN zakazky z ON z.id=d.zakazka_id
               WHERE d.user_id=%s ORDER BY d.datum DESC, d.id DESC LIMIT 100""",
            (uid,),
        )
        if df.empty:
            st.info("Zatím žádné záznamy.")
        else:
            show = df.copy()
            show["Schváleno"] = show["Schváleno"].map({1: "✅", 0: "⏳"})
            st.dataframe(show.drop(columns="id"), use_container_width=True, hide_index=True)
            neschv = df[df["Schváleno"] == 0]
            if not neschv.empty:
                with st.expander("Smazat chybný záznam"):
                    popis = {
                        int(r.id): f"{r.Datum} – {r.Zakázka} – {r.Hodiny} h"
                        for r in neschv.itertuples()
                    }
                    sel = st.selectbox("Záznam", list(popis), format_func=lambda i: popis[i])
                    if st.button("Smazat"):
                        run(
                            "DELETE FROM dochazka WHERE id=%s AND user_id=%s AND schvaleno=0",
                            (int(sel), uid),
                        )
                        st.rerun()


    with tab4:
        if zak.empty:
            st.warning("Nemáš přiřazenou žádnou zakázku.")
        else:
            with st.form("foto", clear_on_submit=True):
                nazev = st.selectbox("Zakázka", zak["nazev"], key="foto_zak")
                files = st.file_uploader(
                    "Vyfoť nebo vyber fotky",
                    type=["jpg", "jpeg", "png", "webp"],
                    accept_multiple_files=True,
                )
                popis = st.text_input("Popis (např. hotová stěna, 2. patro)")
                if st.form_submit_button("📷 Nahrát", use_container_width=True):
                    if not files:
                        st.error("Vyber aspoň jednu fotku.")
                    else:
                        zid = int(zak.loc[zak["nazev"] == nazev, "id"].iloc[0])
                        for f in files:
                            run(
                                "INSERT INTO fotky(user_id, zakazka_id, datum, popis, data) VALUES(%s,%s,%s,%s,%s)",
                                (uid, zid, str(now().date()), popis, psycopg2.Binary(zmensi_foto(f))),
                            )
                        st.success(f"Nahráno fotek: {len(files)}")

            moje = q(
                """SELECT f.datum, f.popis, z.nazev, f.data FROM fotky f
                   JOIN zakazky z ON z.id=f.zakazka_id
                   WHERE f.user_id=%s ORDER BY f.id DESC LIMIT 6""",
                (uid,),
            )
            if not moje.empty:
                st.caption("Tvoje poslední fotky")
                for r in moje.itertuples():
                    st.image(bytes(r.data), caption=f"{r.datum} · {r.nazev}" + (f" · {r.popis}" if r.popis else ""))


# ---------- admin ----------
def vydelek(df):
    df = df.copy()
    for col in ("hodiny", "metry", "sazba"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(float)
    df["vydelek"] = df.apply(
        lambda r: r["metry"] * r["sazba"] if r["typ_sazby"] == METROVA else r["hodiny"] * r["sazba"],
        axis=1,
    )
    return df


def tab_prehled():
    c1, c2 = st.columns(2)
    od = c1.date_input("Od", value=now().date().replace(day=1))
    do = c2.date_input("Do", value=now().date())

    users = q("SELECT id, jmeno FROM users ORDER BY jmeno")
    zakazky = q("SELECT id, nazev FROM zakazky ORDER BY nazev")
    f1, f2 = st.columns(2)
    fu = f1.multiselect("Zaměstnanec", users["jmeno"])
    fz = f2.multiselect("Zakázka", zakazky["nazev"])

    df = q(
        """SELECT d.id, d.datum, u.jmeno, z.nazev, z.typ_sazby, d.hodiny, d.metry,
                  COALESCE(p.sazba, z.sazba) AS sazba, d.schvaleno, d.poznamka
           FROM dochazka d
           JOIN users u ON u.id=d.user_id
           JOIN zakazky z ON z.id=d.zakazka_id
           LEFT JOIN prirazeni p ON p.user_id=d.user_id AND p.zakazka_id=d.zakazka_id
           WHERE d.datum BETWEEN %s AND %s
           ORDER BY d.datum DESC, u.jmeno""",
        (str(od), str(do)),
    )
    if fu:
        df = df[df["jmeno"].isin(fu)]
    if fz:
        df = df[df["nazev"].isin(fz)]

    if df.empty:
        st.info("V tomto období nejsou žádné záznamy.")
        return

    df = vydelek(df)
    m1, m2, m3 = st.columns(3)
    m1.metric("Hodiny", f"{df['hodiny'].sum():.1f}")
    m2.metric("Metry", f"{df['metry'].sum():.1f}")
    m3.metric("K výplatě", f"{df['vydelek'].sum():,.0f} Kč".replace(",", " "))

    st.subheader("Po zaměstnancích")
    po_zam = df.groupby("jmeno").agg(hodiny=("hodiny", "sum"), metry=("metry", "sum"), vydelek=("vydelek", "sum")).reset_index()
    st.dataframe(po_zam, use_container_width=True, hide_index=True)

    st.subheader("Po zakázkách")
    po_zak = df.groupby("nazev").agg(hodiny=("hodiny", "sum"), metry=("metry", "sum"), vydelek=("vydelek", "sum")).reset_index()
    st.dataframe(po_zak, use_container_width=True, hide_index=True)

    st.subheader("Jednotlivé záznamy")
    st.caption("Můžeš opravit hodiny, metry, poznámku a zaškrtnout schválení. Pak dole ulož.")
    edit = df[["id", "datum", "jmeno", "nazev", "hodiny", "metry", "poznamka", "schvaleno"]].copy()
    edit["schvaleno"] = edit["schvaleno"].astype(bool)
    edited = st.data_editor(
        edit,
        hide_index=True,
        use_container_width=True,
        disabled=["id", "datum", "jmeno", "nazev"],
        column_config={
            "schvaleno": st.column_config.CheckboxColumn("Schváleno"),
            "id": None,
        },
        key="edit_dochazka",
    )
    if st.button("💾 Uložit změny", type="primary"):
        run_many([
            (
                "UPDATE dochazka SET hodiny=%s, metry=%s, poznamka=%s, schvaleno=%s WHERE id=%s",
                (nn(r.hodiny), nn(r.metry), nn(r.poznamka), int(r.schvaleno), int(r.id)),
            )
            for r in edited.itertuples()
        ])
        st.success("Uloženo.")
        st.rerun()

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        df.to_excel(xw, sheet_name="Záznamy", index=False)
        po_zam.to_excel(xw, sheet_name="Po zaměstnancích", index=False)
        po_zak.to_excel(xw, sheet_name="Po zakázkách", index=False)
    st.download_button(
        "📥 Export do Excelu",
        buf.getvalue(),
        file_name=f"dochazka_{od}_{do}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


def tab_detail():
    users = q("SELECT id, jmeno FROM users WHERE aktivni=1 ORDER BY jmeno")
    if users.empty:
        st.info("Zatím nejsou žádní zaměstnanci.")
        return

    t = now().date()
    mesice, y, m = [], t.year, t.month
    for _ in range(12):
        mesice.append((y, m))
        m -= 1
        if m == 0:
            m, y = 12, y - 1

    c1, c2 = st.columns(2)
    jmeno = c1.selectbox("Zaměstnanec", users["jmeno"], key="det_user")
    ym = c2.selectbox("Měsíc", mesice, format_func=lambda x: f"{x[1]:02d}/{x[0]}", key="det_mes")
    uid = int(users.loc[users["jmeno"] == jmeno, "id"].iloc[0])
    od = date(ym[0], ym[1], 1)
    do = date(ym[0], ym[1], calendar.monthrange(ym[0], ym[1])[1])

    df = q(
        """SELECT d.id, d.datum, z.nazev, z.typ_sazby, d.prichod, d.odchod, d.hodiny, d.metry,
                  COALESCE(p.sazba, z.sazba) AS sazba, d.schvaleno, d.poznamka
           FROM dochazka d
           JOIN zakazky z ON z.id=d.zakazka_id
           LEFT JOIN prirazeni p ON p.user_id=d.user_id AND p.zakazka_id=d.zakazka_id
           WHERE d.user_id=%s AND d.datum BETWEEN %s AND %s
           ORDER BY d.datum, d.id""",
        (uid, str(od), str(do)),
    )
    if df.empty:
        st.info(f"{jmeno} nemá v tomto měsíci žádné záznamy.")
        return

    df = vydelek(df)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hodiny", f"{df['hodiny'].sum():.1f}")
    m2.metric("Metry", f"{df['metry'].sum():.1f}")
    m3.metric("Dnů", df["datum"].nunique())
    m4.metric("K výplatě", f"{df['vydelek'].sum():,.0f} Kč".replace(",", " "))

    st.subheader("Součet po zakázkách")
    po_zak = (
        df.groupby(["nazev", "typ_sazby"])
        .agg(dnu=("datum", "nunique"), hodiny=("hodiny", "sum"), metry=("metry", "sum"), vydelek=("vydelek", "sum"))
        .reset_index()
        .rename(columns={"nazev": "Zakázka", "typ_sazby": "Sazba", "dnu": "Dnů", "hodiny": "Hodiny", "metry": "Metry", "vydelek": "Výdělek (Kč)"})
        .round(2)
    )
    st.dataframe(po_zak, use_container_width=True, hide_index=True)

    st.subheader("Den po dni")
    den = pd.DataFrame(
        {
            "Den": df["datum"].map(lambda x: f"{CZ_DNY[date.fromisoformat(x).weekday()]} {date.fromisoformat(x).day}.{date.fromisoformat(x).month}."),
            "Zakázka": df["nazev"],
            "Příchod": df["prichod"].map(lambda x: x[11:16] if isinstance(x, str) else "—"),
            "Odchod": df["odchod"].map(lambda x: x[11:16] if isinstance(x, str) else "—"),
            "Hodiny": df["hodiny"].round(2),
            "Metry": df["metry"].round(2),
            "Výdělek": df["vydelek"].round(0),
            "Schváleno": df["schvaleno"].map({1: "✅", 0: "⏳"}),
            "Poznámka": df["poznamka"].fillna(""),
        }
    )
    st.dataframe(den, use_container_width=True, hide_index=True)

    b1, b2 = st.columns(2)
    if b1.button("✅ Schválit celý měsíc", use_container_width=True):
        run(
            """UPDATE dochazka SET schvaleno=1
               WHERE user_id=%s AND datum BETWEEN %s AND %s AND (odchod IS NOT NULL OR prichod IS NULL)""",
            (uid, str(od), str(do)),
        )
        st.rerun()

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        den.to_excel(xw, sheet_name="Den po dni", index=False)
        po_zak.to_excel(xw, sheet_name="Po zakázkách", index=False)
    b2.download_button(
        "📥 Excel",
        buf.getvalue(),
        file_name=f"{jmeno}_{ym[0]}-{ym[1]:02d}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True,
    )
    st.caption("Chybný záznam oprav v záložce Přehled (úprava hodin, metrů a poznámky).")


def tab_fotky_admin():
    zak = q("SELECT id, nazev FROM zakazky ORDER BY nazev")
    if zak.empty:
        st.info("Zatím nejsou žádné zakázky.")
        return
    nazev = st.selectbox("Zakázka", zak["nazev"], key="adm_foto_zak")
    zid = int(zak.loc[zak["nazev"] == nazev, "id"].iloc[0])
    limit = st.number_input("Kolik posledních fotek zobrazit", min_value=2, max_value=60, value=12, step=2)
    fot = q(
        """SELECT f.id, f.datum, f.popis, u.jmeno, f.data FROM fotky f
           JOIN users u ON u.id=f.user_id
           WHERE f.zakazka_id=%s ORDER BY f.id DESC LIMIT %s""",
        (zid, int(limit)),
    )
    if fot.empty:
        st.info("K této zakázce zatím nejsou žádné fotky.")
        return
    cols = st.columns(2)
    for i, r in enumerate(fot.itertuples()):
        with cols[i % 2]:
            st.image(bytes(r.data), caption=f"{r.datum} · {r.jmeno}" + (f" · {r.popis}" if r.popis else ""))
            if st.button("Smazat", key=f"delfoto_{r.id}"):
                run("DELETE FROM fotky WHERE id=%s", (int(r.id),))
                st.rerun()


def tab_zakazky():
    with st.form("nova_zakazka", clear_on_submit=True):
        st.subheader("Nová zakázka")
        nazev = st.text_input("Název (např. Rekonstrukce Novák, Ostrava)")
        klient = st.text_input("Klient")
        typ = st.radio("Typ sazby", [HODINOVA, METROVA], horizontal=True)
        sazba = st.number_input("Sazba (Kč za hodinu nebo za metr)", min_value=0.0, step=10.0)
        if st.form_submit_button("Přidat"):
            if not nazev.strip():
                st.error("Zadej název.")
            else:
                try:
                    run(
                        "INSERT INTO zakazky(nazev, klient, typ_sazby, sazba) VALUES(%s,%s,%s,%s)",
                        (nazev.strip(), klient, typ, float(sazba)),
                    )
                    st.rerun()
                except psycopg2.IntegrityError:
                    st.error("Taková zakázka už existuje.")

    st.subheader("Seznam zakázek")
    df = q("SELECT id, nazev, klient, typ_sazby, sazba, aktivni FROM zakazky ORDER BY aktivni DESC, nazev")
    if df.empty:
        return
    df["aktivni"] = df["aktivni"].astype(bool)
    edited = st.data_editor(
        df,
        hide_index=True,
        use_container_width=True,
        disabled=["id", "nazev", "typ_sazby"],
        column_config={"id": None, "aktivni": st.column_config.CheckboxColumn("Aktivní")},
        key="edit_zakazky",
    )
    if st.button("💾 Uložit zakázky"):
        run_many([
            (
                "UPDATE zakazky SET klient=%s, sazba=%s, aktivni=%s WHERE id=%s",
                (nn(r.klient), float(nn(r.sazba) or 0), int(r.aktivni), int(r.id)),
            )
            for r in edited.itertuples()
        ])
        st.success("Uloženo.")
        st.rerun()


def tab_zamestnanci():
    with st.form("novy_user", clear_on_submit=True):
        st.subheader("Nový zaměstnanec")
        j = st.text_input("Jméno (pod ním se bude přihlašovat)")
        h = st.text_input("Heslo (min. 6 znaků)", type="password")
        role = st.selectbox("Role", ["zamestnanec", "admin"])
        if st.form_submit_button("Přidat"):
            if not j.strip() or len(h) < 6:
                st.error("Zadej jméno a heslo (min. 6 znaků).")
            else:
                try:
                    create_user(j, h, role)
                    st.rerun()
                except psycopg2.IntegrityError:
                    st.error("Toto jméno už existuje.")

    st.subheader("Seznam")
    df = q("SELECT id, jmeno, role, aktivni FROM users ORDER BY aktivni DESC, jmeno")
    df["aktivni"] = df["aktivni"].astype(bool)
    edited = st.data_editor(
        df,
        hide_index=True,
        use_container_width=True,
        disabled=["id", "jmeno", "role"],
        column_config={"id": None, "aktivni": st.column_config.CheckboxColumn("Aktivní")},
        key="edit_users",
    )
    if st.button("💾 Uložit zaměstnance"):
        run_many([
            ("UPDATE users SET aktivni=%s WHERE id=%s", (int(r.aktivni), int(r.id)))
            for r in edited.itertuples()
            if not (int(r.id) == st.session_state.user["id"] and not r.aktivni)
        ])
        st.success("Uloženo.")
        st.rerun()

    with st.expander("Změnit heslo zaměstnanci"):
        with st.form("reset_pw", clear_on_submit=True):
            kdo = st.selectbox("Kdo", df["jmeno"])
            nove = st.text_input("Nové heslo", type="password")
            if st.form_submit_button("Změnit"):
                if len(nove) < 6:
                    st.error("Min. 6 znaků.")
                else:
                    uid = int(df.loc[df["jmeno"] == kdo, "id"].iloc[0])
                    set_password(uid, nove)
                    st.success("Heslo změněno.")


def tab_prirazeni():
    zak = q("SELECT id, nazev, typ_sazby, sazba FROM zakazky WHERE aktivni=1 ORDER BY nazev")
    users = q("SELECT id, jmeno FROM users WHERE aktivni=1 AND role='zamestnanec' ORDER BY jmeno")
    if zak.empty or users.empty:
        st.info("Nejdřív vytvoř aspoň jednu zakázku a jednoho zaměstnance.")
        return

    nazev = st.selectbox("Zakázka", zak["nazev"])
    z = zak[zak["nazev"] == nazev].iloc[0]
    jednotka = "Kč/m" if z["typ_sazby"] == METROVA else "Kč/h"
    st.caption(f"Typ: {z['typ_sazby']} · výchozí sazba {z['sazba']:.0f} {jednotka}. "
               "Pokud má někdo jinou sazbu, vyplň ji. Prázdné = výchozí.")

    pr = q("SELECT user_id, sazba FROM prirazeni WHERE zakazka_id=%s", (int(z["id"]),))
    mapa = dict(zip(pr["user_id"], pr["sazba"]))
    tab = pd.DataFrame(
        {
            "id": users["id"],
            "Zaměstnanec": users["jmeno"],
            "Přiřazen": users["id"].isin(mapa.keys()),
            "Vlastní sazba": users["id"].map(mapa),
        }
    )
    edited = st.data_editor(
        tab,
        hide_index=True,
        use_container_width=True,
        disabled=["id", "Zaměstnanec"],
        column_config={"id": None},
        key=f"prir_{z['id']}",
    )
    if st.button("💾 Uložit přiřazení"):
        stmts = [("DELETE FROM prirazeni WHERE zakazka_id=%s", (int(z["id"]),))]
        for r in edited.itertuples(index=False):
            if r[2]:
                sazba = None if pd.isna(r[3]) else float(r[3])
                stmts.append((
                    "INSERT INTO prirazeni(user_id, zakazka_id, sazba) VALUES(%s,%s,%s)",
                    (int(r[0]), int(z["id"]), sazba),
                ))
        run_many(stmts)
        st.success("Uloženo.")


def page_admin():
    t1, t2, t3, t4, t5, t6 = st.tabs(
        ["👤 Zaměstnanec", "📊 Přehled", "📷 Fotky", "🏗️ Zakázky", "👷 Lidé", "🔗 Přiřazení"]
    )
    with t1:
        tab_detail()
    with t2:
        tab_prehled()
    with t3:
        tab_fotky_admin()
    with t4:
        tab_zakazky()
    with t5:
        tab_zamestnanci()
    with t6:
        tab_prirazeni()


# ---------- hlavní ----------
def main():
    if not db_url():
        st.error("Chybí nastavení DATABASE_URL. Viz návod.")
        st.stop()
    init_db()
    user = st.session_state.get("user")
    if not user:
        page_login()
        return

    top1, top2 = st.columns([3, 1])
    top1.markdown(f"### 🏗️ {user['jmeno']}")
    if top2.button("Odhlásit"):
        st.session_state.clear()
        st.rerun()

    if user["role"] == "admin":
        page_admin()
    else:
        page_zamestnanec(user)


main()
