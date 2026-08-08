#!/usr/bin/env python3
"""정본인 PostgreSQL 스키마에서 MariaDB 초기 스키마를 생성한다.

스키마를 설계하고 계속 발전시키는 곳은 PostgreSQL 쪽이므로, MariaDB 버전은 손으로
유지하지 않고 생성한다. migrations/001_init.sql을 고쳤다면 이 스크립트를 다시
돌리고 결과를 커밋한다. 모든 예외 처리가 이 파일 안에 있으므로 출력은 재현
가능하고, 어느 줄을 손으로 고쳤는지 아무도 기억할 필요가 없다.

    python3 scripts/pg2mariadb-schema.py

읽기: api/internal/database/migrations/001_init.sql
쓰기: api/internal/database/migrations/mariadb/001_init.sql

출력은 MariaDB를 겨냥한다. MySQL도 같은 파일을 실행한다. MySQL이 거부하는 소수의
구문 — 대부분의 DDL에 붙는 IF NOT EXISTS, MariaDB의 페이지 압축 속성 — 은
번역기가 실행 도중 재작성한다(internal/database/dialect 참고).

두 스키마가 의도적으로 다른 지점:

  * TimescaleDB 하이퍼테이블과 PostgreSQL 선언적 파티셔닝은 같은 키를 쓰는
    RANGE COLUMNS 파티셔닝이 된다. 모든 유니크 키가 파티션 컬럼을 포함해야
    하므로, 해당 테이블의 기본 키에 그 컬럼이 추가된다.
  * enum 타입은 컬럼 수준 ENUM으로 인라인된다. 독립적으로 CREATE할 enum 타입이
    없기 때문이다.
  * text[] 컬럼은 PostgreSQL 배열 리터럴을 담은 TEXT가 된다. 덕분에 lib/pq의
    배열 Scanner/Valuer가 두 백엔드에서 그대로 동작한다.
  * 부분 인덱스는 WHERE 술어를 잃는다(보장이 아니라 최적화이므로). 단 UNIQUE인
    경우에는 그 술어가 *바로* 보장이므로, 생성 컬럼과 평범한 유니크 인덱스로
    바꾼다.

    그 컬럼들은 STORED가 아니라 VIRTUAL이다. 아무도 그 값을 조회하지 않고 —
    유니크 인덱스를 담기 위해서만 존재한다 — 실체화하면 공간만 낭비된다. 게다가
    MySQL은 STORED 생성 컬럼이 참조하는 컬럼에 ON DELETE CASCADE 외래 키를
    허용하지 않는데, 여기 해당하는 컬럼이 여럿이다.
  * GIN/트라이그램 인덱스는 버린다. InnoDB에 대응물이 없다.
  * updated_at 트리거는 ON UPDATE CURRENT_TIMESTAMP(6)이 된다.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "api/internal/database/migrations/001_init.sql"
TARGET = ROOT / "api/internal/database/migrations/mariadb/001_init.sql"

# InnoDB DYNAMIC 행 포맷의 인덱스 키 상한은 3072바이트다.
MAX_KEY_BYTES = 3072
BYTES_PER_CHAR = 4  # utf8mb4
# 비유니크 인덱스에서 TEXT 컬럼에 쓸 접두사 길이. 선택도를 확보할 만큼 길면서
# 키 예산 안에 넉넉히 들어갈 만큼 짧다.
TEXT_INDEX_PREFIX = 191

# InnoDB 페이지 압축을 적용할 테이블과 사용할 zlib 레벨.
#
# TimescaleDB 청크 압축에 대한 MySQL 계열의 답이다. 로그 행은 반복이 극심하다.
# 같은 유저 에이전트, 같은 호스트, 같은 URI 형태가 계속 나온다. 실제 형태의 액세스
# 로그 20만 행으로 측정했을 때 테이블이 165MB에서 36MB로 줄었다. 4.6배다.
#
# 기본값 6이 아니라 레벨 1을 쓴다. 같은 데이터에서 두 레벨의 디스크 크기는 같은데
# 레벨 6은 쓰기에 2.7배가 걸린다. 로그 수집이 이 애플리케이션에서 가장 쓰기가 많은
# 작업이므로, 여기서는 싼 쪽이 명백히 낫다.
#
# 페이지 압축에는 sparse 파일에 hole punch가 가능한 파일시스템이 필요하다. ext4,
# xfs, btrfs 모두 가능하다. 지원하지 않는 환경에서는 InnoDB가 페이지를 압축하되
# 전체 크기로 기록하므로, 오류가 아니라 약간의 CPU 낭비로 끝난다.
#
# 대용량 테이블만 올린다. 압축은 버퍼 풀에서 빗나가는 페이지 읽기마다 CPU를
# 쓰는데, 끊임없이 읽히고 크기는 킬로바이트 단위인 작은 설정 테이블에까지 치를
# 값은 아니다.
COMPRESSED_TABLES = {
    "logs_partitioned",
    "logs",
    "system_logs",
    "audit_logs",
}
PAGE_COMPRESSION_LEVEL = 1


# ---------------------------------------------------------------------------
# 문장 분리
# ---------------------------------------------------------------------------

def split_statements(sql: str) -> list[str]:
    """최상위 세미콜론 기준으로 나눈다. 따옴표와 $$ 본문은 존중한다."""
    out, buf = [], []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "\\":
                    j += 2
                    continue
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            buf.append(sql[i:j])
            i = j
        elif c == '"':
            j = sql.find('"', i + 1)
            j = n if j < 0 else j + 1
            buf.append(sql[i:j])
            i = j
        elif c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            buf.append(sql[i:j])
            i = j
        elif c == "$":
            m = re.match(r"\$[A-Za-z_0-9]*\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                j = n if j < 0 else j + len(tag)
                buf.append(sql[i:j])
                i = j
            else:
                buf.append(c)
                i += 1
        elif c == ";":
            out.append("".join(buf).strip())
            buf = []
            i += 1
        else:
            buf.append(c)
            i += 1
    if "".join(buf).strip():
        out.append("".join(buf).strip())
    return [s for s in out if s]


def strip_line_comments(sql: str) -> tuple[str, str]:
    """(선행 주석 블록, 코드)를 돌려준다. 코드에서는 -- 주석을 모두 제거한다.

    원본의 문장 앞에는 이유를 설명하는 여러 줄이 붙어 있는 경우가 많다. 그 설명은
    생성 파일로 옮길 가치가 있지만, 패턴이 문장 시작에 고정된 파서들에게까지
    도달해서는 안 된다.
    """
    lead: list[str] = []
    code: list[str] = []
    seen_code = False
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            code.append(sql[i:j])
            seen_code = True
            i = j
        elif c == '"':
            j = sql.find('"', i + 1)
            j = n if j < 0 else j + 1
            code.append(sql[i:j])
            seen_code = True
            i = j
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            if not seen_code:
                lead.append(sql[i:j])
            i = j
        else:
            if not c.isspace():
                seen_code = True
            code.append(c)
            i += 1
    return "\n".join(lead), " ".join("".join(code).split())


def split_top_level_commas(body: str) -> list[str]:
    """CREATE TABLE 본문을 컬럼과 제약 조건 절로 나눈다."""
    parts, buf, depth = [], [], 0
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "'":
            j = i + 1
            while j < n:
                if body[j] == "'":
                    if j + 1 < n and body[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            buf.append(body[i:j])
            i = j
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if "".join(buf).strip():
        parts.append("".join(buf).strip())
    return parts


# ---------------------------------------------------------------------------
# 타입과 기본값 대응
# ---------------------------------------------------------------------------

SCALAR_TYPES = [
    (r"^timestamp\s+with(out)?\s+time\s+zone$", "DATETIME(6)"),
    (r"^timestamptz$", "DATETIME(6)"),
    (r"^timestamp$", "DATETIME(6)"),
    (r"^date$", "DATE"),
    (r"^time\s+with(out)?\s+time\s+zone$", "TIME"),
    (r"^time$", "TIME"),
    (r"^uuid$", "VARCHAR(36)"),
    (r"^boolean$", "BOOLEAN"),
    (r"^smallint$", "SMALLINT"),
    (r"^integer$", "INT"),
    (r"^int$", "INT"),
    (r"^bigint$", "BIGINT"),
    (r"^serial$", "INT AUTO_INCREMENT"),
    (r"^bigserial$", "BIGINT AUTO_INCREMENT"),
    (r"^double\s+precision$", "DOUBLE"),
    (r"^real$", "FLOAT"),
    (r"^numeric\((\d+),\s*(\d+)\)$", r"DECIMAL(\1,\2)"),
    (r"^numeric\((\d+)\)$", r"DECIMAL(\1)"),
    (r"^numeric$", "DECIMAL(20,6)"),
    (r"^character\s+varying\((\d+)\)$", r"VARCHAR(\1)"),
    (r"^character\s+varying$", "TEXT"),
    (r"^varchar\((\d+)\)$", r"VARCHAR(\1)"),
    (r"^character\((\d+)\)$", r"CHAR(\1)"),
    (r"^jsonb$", "JSON"),
    (r"^json$", "JSON"),
    # No native inet: the longest textual IPv6 with a zone still fits in 45.
    (r"^inet$", "VARCHAR(45)"),
    (r"^cidr$", "VARCHAR(49)"),
    (r"^macaddr$", "VARCHAR(17)"),
    (r"^bytea$", "LONGBLOB"),
    (r"^text$", "TEXT"),
]


def map_type(pg_type: str, enums: dict[str, list[str]]) -> str:
    t = " ".join(pg_type.strip().split())
    bare = t[len("public."):] if t.lower().startswith("public.") else t

    # 배열은 PostgreSQL 리터럴 형태를 유지한다. lib/pq의 배열 코덱이 그대로
    # 왕복하게 하기 위해서다. 바뀌는 것은 저장 타입뿐이다.
    if bare.endswith("[]"):
        return "TEXT"

    if bare.lower() in enums:
        values = ", ".join("'%s'" % v for v in enums[bare.lower()])
        return "ENUM(%s)" % values

    for pattern, replacement in SCALAR_TYPES:
        m = re.match(pattern, t, re.IGNORECASE)
        if m:
            return re.sub(pattern, replacement, t, flags=re.IGNORECASE).upper() \
                if "\\" in replacement else replacement

    raise SystemExit("unmapped PostgreSQL type: %r" % pg_type)


def map_default(expr: str, enums: dict[str, list[str]]) -> str | None:
    """DEFAULT 식을 번역한다. None을 돌려주면 그 기본값을 버린다."""
    e = expr.strip()

    # Postgres 캐스트를 제거한다: 'x'::character varying, '{}'::text[], ...
    e = re.sub(r"::\s*public\.[A-Za-z_0-9]+(\[\])?", "", e)
    e = re.sub(r"::\s*(character\s+varying|double\s+precision|timestamp\s+with(out)?\s+time\s+zone)"
               r"(\(\d+\))?(\[\])?", "", e, flags=re.IGNORECASE)
    e = re.sub(r"::\s*[A-Za-z_0-9]+(\(\d+(,\s*\d+)?\))?(\[\])?", "", e)
    e = e.strip()

    low = e.lower()
    if low in ("now()", "current_timestamp", "current_timestamp()"):
        return "CURRENT_TIMESTAMP(6)"
    if low in ("gen_random_uuid()", "uuid_generate_v4()", "public.uuid_generate_v4()"):
        # 괄호를 씌우는 이유: MySQL은 함수 기본값을 식 형태로만 받아준다.
        # MariaDB는 둘 다 받으므로 한 형태로 양쪽을 커버한다.
        return "(UUID())"
    if low == "null":
        return "NULL"

    # ARRAY['a','b'] 리터럴은 lib/pq가 만들었을 PostgreSQL 배열 리터럴
    # 텍스트가 된다.
    m = re.match(r"^ARRAY\[(.*)\]$", e, re.IGNORECASE | re.DOTALL)
    if m:
        items = [x.strip() for x in split_top_level_commas(m.group(1))] if m.group(1).strip() else []
        rendered = ",".join('"%s"' % x.strip("'").replace("''", "'").replace('"', '\\"') for x in items)
        return "'{%s}'" % rendered

    if e.startswith("'") or re.match(r"^-?[0-9.]+$", e) or low in ("true", "false"):
        # JSON 컬럼은 식 형태가 아니면 맨 리터럴을 기본값으로 둘 수 없다.
        # 괄호가 식 기본값으로 만들어 준다.
        return e

    if re.match(r"^[A-Za-z_0-9]+\(\)$", e):
        return None  # 알 수 없는 함수 기본값: 추측하지 말고 버린다
    return e


def needs_expression_default(mysql_type: str) -> bool:
    """TEXT/BLOB/JSON 기본값은 식 형태로 써야 한다."""
    head = mysql_type.split("(")[0].upper()
    return head in {"TEXT", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT", "JSON", "BLOB", "LONGBLOB"}


# ---------------------------------------------------------------------------
# 원본 파싱
# ---------------------------------------------------------------------------

def parse_enums(statements: list[str]) -> dict[str, list[str]]:
    enums: dict[str, list[str]] = {}
    for stmt in statements:
        for m in re.finditer(
            r"CREATE\s+TYPE\s+(?:public\.)?([A-Za-z_0-9]+)\s+AS\s+ENUM\s*\((.*?)\)",
            stmt, re.IGNORECASE | re.DOTALL,
        ):
            name = m.group(1).lower()
            values = re.findall(r"'([^']*)'", m.group(2))
            enums[name] = values
    return enums


PARTITION_CHILD = re.compile(r"^(logs_p(?:\d{4}_\d{2}|_default)|stats_hourly_p(?:\d{4}_\d{2}|_default))$")


def parse_partition_ranges(statements: list[str]) -> dict[str, list[tuple[str, str]]]:
    """ATTACH 문장들에서 파티션 부모 테이블의 경계값을 복원한다."""
    ranges: dict[str, list[tuple[str, str]]] = {}
    for stmt in statements:
        m = re.search(
            r"ALTER\s+TABLE\s+ONLY\s+(?:public\.)?([A-Za-z_0-9]+)\s+ATTACH\s+PARTITION\s+"
            r"(?:public\.)?([A-Za-z_0-9]+)\s+FOR\s+VALUES\s+FROM\s*\('([^']+)'\)\s*TO\s*\('([^']+)'\)",
            stmt, re.IGNORECASE,
        )
        if m:
            parent, child, _from, to = m.groups()
            ranges.setdefault(parent, []).append((child, to))
    for parent in ranges:
        ranges[parent].sort(key=lambda cv: cv[1])
    return ranges


class Table:
    def __init__(self, name: str):
        self.name = name
        self.columns: list[tuple[str, str, str]] = []  # (name, mysql type, tail)
        self.column_types: dict[str, str] = {}
        self.constraints: list[str] = []
        self.partition_by: str | None = None
        self.generated: list[str] = []
        self.extra_keys: list[str] = []
        self.doc: str = ""
        # Foreign keys are always emitted after every table exists. MariaDB
        # rejects a table whose FK target has not been created yet, and the
        # tables are written in alphabetical order.
        self.foreign_keys: list[tuple[str, str]] = []

    def add_generated(self, name: str, definition: str) -> None:
        if any(g.split()[0] == name for g in self.generated):
            return
        self.generated.append(definition)

    def add_key(self, name: str, definition: str) -> None:
        if any(re.search(r"KEY %s \(" % re.escape(name), k) for k in self.extra_keys):
            return
        self.extra_keys.append(definition)


def parse_tables(prepared: list[tuple[str, str]], enums: dict[str, list[str]]) -> dict[str, Table]:
    tables: dict[str, Table] = {}
    for lead, stmt in prepared:
        # 선택 그룹 하나가 아니라 두 번 시도한다. 탐욕적인 본문 캡처는
        # `) PARTITION BY RANGE (created_at)`까지 삼켜 버리고 테이블을
        # 비파티션으로 보고하므로, 꼬리를 고정한 파티션 형태를 먼저 시도해야
        # 한다.
        m = re.match(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?([A-Za-z_0-9]+)\s*\((.*)\)\s*"
            r"PARTITION\s+BY\s+RANGE\s*\(([A-Za-z_0-9\"]+)\)\s*$",
            stmt, re.IGNORECASE | re.DOTALL,
        )
        if m:
            name, body, part_col = m.groups()
        else:
            m = re.match(
                r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?([A-Za-z_0-9]+)\s*\((.*)\)\s*$",
                stmt, re.IGNORECASE | re.DOTALL,
            )
            if not m:
                continue
            name, body = m.groups()
            part_col = None
        if PARTITION_CHILD.match(name):
            continue  # 부모 테이블의 PARTITION 절이 된다

        table = Table(name)
        table.doc = lead
        table.partition_by = part_col.strip('"') if part_col else None

        for clause in split_top_level_commas(body):
            if re.match(r"^(CONSTRAINT|PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY|EXCLUDE)\b",
                        clause, re.IGNORECASE):
                translated = translate_table_constraint(clause, enums)
                if not translated:
                    continue
                fk = re.match(r"^(?:CONSTRAINT (\S+) )?(FOREIGN KEY .*)$", translated)
                if fk:
                    table.foreign_keys.append(
                        (fk.group(1) or "fk_%s_%d" % (table.name, len(table.foreign_keys)),
                         fk.group(2)))
                else:
                    table.constraints.append(translated)
                continue

            col = parse_column(clause, enums)
            if col:
                cname, ctype, ctail, cref = col
                # TEXT 컬럼에 인라인으로 붙은 UNIQUE는 접두사 길이를 가질 수
                # 없다. MySQL은 그것을 요구하고 MariaDB는 키를 조용히 USING
                # HASH로 바꿔 넘긴다. 접두사 단계가 길이를 명시적으로 정할 수
                # 있도록 테이블 수준 키로 승격한다.
                if "UNIQUE" in ctail and ctype.split("(")[0].upper() in (
                        "TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT", "JSON"):
                    ctail = re.sub(r"\s*\bUNIQUE\b", "", ctail).strip()
                    table.extra_keys.append(
                        "UNIQUE KEY uq_%s_%s (%s)" % (table.name, cname, cname))
                table.columns.append((cname, ctype, ctail))
                table.column_types[cname] = ctype
                if cref:
                    table.foreign_keys.append(
                        ("fk_%s_%s" % (table.name, cname),
                         "FOREIGN KEY (%s) REFERENCES %s" % (cname, cref)))

        tables[name] = table
    return tables



# Keywords that end a DEFAULT expression. Matching these with a regex over the
# raw text is not safe: a default like 'Please complete the security check to
# continue.' contains the word CHECK inside a string literal, and an earlier
# version of this script truncated the value there.
TAIL_KEYWORDS = ("NOT", "NULL", "PRIMARY", "UNIQUE", "REFERENCES", "CHECK",
                 "CONSTRAINT", "COLLATE", "GENERATED")


def tokenize_tail(tail: str) -> list[tuple[str, int, int]]:
    """Tokenize a column's trailing modifiers, keeping literals atomic."""
    toks: list[tuple[str, int, int]] = []
    i, n = 0, len(tail)
    while i < n:
        c = tail[i]
        if c.isspace():
            i += 1
        elif c == "'":
            j = i + 1
            while j < n:
                if tail[j] == "'":
                    if j + 1 < n and tail[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            toks.append(("str", i, j))
            i = j
        elif c.isalnum() or c == "_":
            j = i
            while j < n and (tail[j].isalnum() or tail[j] == "_" or tail[j] == "."):
                j += 1
            toks.append(("word", i, j))
            i = j
        else:
            toks.append(("punct", i, i + 1))
            i += 1
    return toks


def parse_column_modifiers(tail: str) -> dict[str, str]:
    """Split a column tail into its modifiers, keyed by canonical name."""
    toks = tokenize_tail(tail)
    out: dict[str, str] = {}

    def word_at(k: int) -> str:
        kind, a, b = toks[k]
        return tail[a:b].upper() if kind == "word" else ""

    i = 0
    while i < len(toks):
        w = word_at(i)
        if w == "NOT" and i + 1 < len(toks) and word_at(i + 1) == "NULL":
            out["NOT NULL"] = ""
            i += 2
        elif w == "PRIMARY" and i + 1 < len(toks) and word_at(i + 1) == "KEY":
            out["PRIMARY KEY"] = ""
            i += 2
        elif w == "UNIQUE":
            out["UNIQUE"] = ""
            i += 1
        elif w == "DEFAULT":
            j, depth = i + 1, 0
            while j < len(toks):
                kind, a, b = toks[j]
                frag = tail[a:b]
                if kind == "punct" and frag in "([":
                    depth += 1
                elif kind == "punct" and frag in ")]":
                    depth -= 1
                elif depth == 0 and j > i + 1 and word_at(j) in TAIL_KEYWORDS:
                    break
                j += 1
            out["DEFAULT"] = tail[toks[i + 1][1]:toks[j - 1][2]].strip()
            i = j
        elif w == "REFERENCES":
            j = i + 1
            while j < len(toks):
                if word_at(j) in ("CHECK", "CONSTRAINT", "DEFAULT"):
                    break
                j += 1
            out["REFERENCES"] = tail[toks[i + 1][1]:toks[j - 1][2]].strip()
            i = j
        else:
            i += 1
    return out



COLUMN_RE = re.compile(r'^("?[A-Za-z_0-9]+"?)\s+(.*)$', re.DOTALL)


def parse_column(clause: str, enums: dict[str, list[str]]) -> tuple[str, str, str, str | None] | None:
    m = COLUMN_RE.match(clause.strip())
    if not m:
        return None
    name = m.group(1).strip('"')
    rest = " ".join(m.group(2).split())

    type_match = re.match(
        r"^((?:public\.)?[A-Za-z_0-9]+(?:\s+(?:varying|precision|with(?:out)?\s+time\s+zone))*"
        r"(?:\(\d+(?:,\s*\d+)?\))?(?:\[\])*)",
        rest, re.IGNORECASE,
    )
    if not type_match:
        return None
    pg_type = type_match.group(1)
    tail = rest[len(pg_type):].strip()
    mysql_type = map_type(pg_type, enums)

    modifiers = parse_column_modifiers(tail)

    pieces: list[str] = []
    if "DEFAULT" in modifiers:
        default = map_default(modifiers["DEFAULT"], enums)
        if default is not None:
            already_expression = default.startswith("(")
            if not already_expression and needs_expression_default(mysql_type) \
                    and not default.upper().startswith("CURRENT_TIMESTAMP"):
                default = "(%s)" % default
            pieces.append("DEFAULT %s" % default)
    if "NOT NULL" in modifiers:
        pieces.insert(0, "NOT NULL")
    if "PRIMARY KEY" in modifiers:
        pieces.append("PRIMARY KEY")
    if "UNIQUE" in modifiers:
        pieces.append("UNIQUE")
    reference = None
    if "REFERENCES" in modifiers:
        reference = re.sub(r"^(?:public\.)?", "", modifiers["REFERENCES"].strip())

    # NOT NULL must precede DEFAULT for readability but MariaDB accepts either;
    # keep the canonical order.
    ordered = []
    for want in ("NOT NULL",):
        if want in pieces:
            ordered.append(want)
            pieces.remove(want)
    ordered.extend(pieces)

    return name, mysql_type, " ".join(ordered), reference


def translate_table_constraint(clause: str, enums: dict[str, list[str]]) -> str | None:
    c = " ".join(clause.split())

    m = re.match(r"^CONSTRAINT\s+([A-Za-z_0-9]+)\s+(.*)$", c, re.IGNORECASE)
    name, rest = (m.group(1), m.group(2)) if m else (None, c)

    if re.match(r"^PRIMARY\s+KEY", rest, re.IGNORECASE):
        cols = re.search(r"\((.*)\)", rest).group(1)
        return "PRIMARY KEY (%s)" % normalise_columns(cols)

    if re.match(r"^UNIQUE", rest, re.IGNORECASE):
        cols = normalise_columns(re.search(r"\((.*)\)", rest).group(1))
        # PostgreSQL is happy with an anonymous UNIQUE(...); naming it keeps the
        # key addressable, both for a later ALTER and for the prefix pass below.
        if not name:
            name = "uq_%s" % "_".join(c.strip('"') for c in cols.split(", "))
        return "UNIQUE KEY %s (%s)" % (name, cols)

    if re.match(r"^CHECK", rest, re.IGNORECASE):
        translated = translate_check(rest)
        if translated is None:
            return None
        return "CONSTRAINT %s %s" % (name, translated) if name else translated

    if re.match(r"^FOREIGN\s+KEY", rest, re.IGNORECASE):
        fk = re.sub(r"REFERENCES\s+public\.", "REFERENCES ", rest, flags=re.IGNORECASE)
        return "CONSTRAINT %s %s" % (name, fk) if name else fk

    return None


def translate_check(expr: str) -> str | None:
    """`CHECK ((col)::text = ANY ((ARRAY[...])::text[]))`를 `CHECK (col IN (...))`으로 바꾼다."""
    m = re.search(r"\(?\(([A-Za-z_0-9]+)\)?(?:::text)?\s*=\s*ANY\s*\(\s*\(?\s*ARRAY\[(.*?)\]",
                  expr, re.IGNORECASE | re.DOTALL)
    if m:
        col = m.group(1)
        values = []
        for item in split_top_level_commas(m.group(2)):
            item = re.sub(r"::\s*[A-Za-z_0-9\[\]\s]+$", "", item.strip()).strip()
            if item:
                values.append(item)
        if not values:
            return None
        return "CHECK (%s IN (%s))" % (col, ", ".join(values))

    body = re.sub(r"::\s*[A-Za-z_0-9\[\]\s]+", "", expr)
    if "ANY" in body.upper() or "~" in body:
        return None  # 지원하지 않는 술어 형태. 잘못 번역하느니 버린다
    return " ".join(body.split())


def normalise_columns(cols: str) -> str:
    return ", ".join(c.strip().strip('"') for c in cols.split(","))


# ---------------------------------------------------------------------------
# 인덱스 번역
# ---------------------------------------------------------------------------

INDEX_RE = re.compile(
    r"^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_0-9]+)\s+"
    r"ON\s+(?:ONLY\s+)?(?:public\.)?([A-Za-z_0-9]+)\s+"
    r"(?:USING\s+([A-Za-z_0-9]+)\s+)?\((.*?)\)\s*(?:WHERE\s+(.*))?$",
    re.IGNORECASE | re.DOTALL,
)


def type_key_bytes(mysql_type: str) -> int:
    head = mysql_type.split("(")[0].upper()
    m = re.search(r"\((\d+)", mysql_type)
    size = int(m.group(1)) if m else 0
    if head == "VARCHAR":
        return size * BYTES_PER_CHAR + 2
    if head == "CHAR":
        return size * BYTES_PER_CHAR
    if head in ("TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT", "JSON"):
        return TEXT_INDEX_PREFIX * BYTES_PER_CHAR + 2
    if head in ("BIGINT", "DOUBLE", "DATETIME"):
        return 8
    if head in ("INT", "FLOAT", "DATE"):
        return 4
    if head in ("SMALLINT", "ENUM"):
        return 2
    return 1


def index_column_spec(table: Table, col: str, unique: bool, budget: int) -> tuple[str, int]:
    """인덱스 컬럼 하나를 렌더링한다. 타입이 필요로 하면 접두사 길이를 붙인다."""
    name = col.strip().strip('"')
    direction = ""
    dm = re.match(r"^(.*?)\s+(ASC|DESC)$", name, re.IGNORECASE)
    if dm:
        name, direction = dm.group(1).strip().strip('"'), " " + dm.group(2).upper()

    mysql_type = table.column_types.get(name, "TEXT")
    head = mysql_type.split("(")[0].upper()

    if head in ("TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT"):
        # 접두사에 건 유니크 인덱스는 그 접두사에 대해서만 유일성을 강제한다.
        # 그래서 해당 컬럼에는 키 예산에서 들어가는 만큼을 최대한 준다.
        prefix = min(budget // BYTES_PER_CHAR, 768) if unique else TEXT_INDEX_PREFIX
        prefix = max(prefix, 1)
        return "%s(%d)%s" % (name, prefix, direction), prefix * BYTES_PER_CHAR + 2

    return "%s%s" % (name, direction), type_key_bytes(mysql_type)


def translate_index(stmt: str, tables: dict[str, Table]) -> str | None:
    m = INDEX_RE.match(" ".join(stmt.split()))
    if not m:
        return None
    unique, name, table_name, method, cols, where = m.groups()
    unique = bool(unique)

    if table_name not in tables:
        return None  # index on a partition child, or a table this file drops
    table = tables[table_name]

    if method and method.lower() in ("gin", "gist", "brin", "spgist"):
        return "-- skipped (%s 인덱스는 대응물이 없어 건너뜀): %s" % (method.lower(), name)

    col_list = split_top_level_commas(cols)

    # 식 인덱스. 이 스키마가 쓰는 두 형태는 모두 제약을 표현하기 위해 존재하므로,
    # 둘 다 생성 컬럼으로 재현한다.
    if any("(" in c or c.strip().lower() == "true" for c in col_list):
        return translate_expression_index(unique, name, table, col_list)

    if where and unique:
        return translate_partial_unique_index(name, table, col_list, where)

    budget = MAX_KEY_BYTES
    fixed = sum(type_key_bytes(table.column_types.get(c.strip().strip('"').split()[0], "TEXT"))
                for c in col_list
                if table.column_types.get(c.strip().strip('"').split()[0], "TEXT").split("(")[0].upper()
                not in ("TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT"))
    text_count = max(1, len(col_list) - sum(
        1 for c in col_list
        if table.column_types.get(c.strip().strip('"').split()[0], "TEXT").split("(")[0].upper()
        not in ("TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT")))
    per_text = max(64 * BYTES_PER_CHAR, (MAX_KEY_BYTES - fixed) // text_count)

    specs = []
    for c in col_list:
        spec, used = index_column_spec(table, c, unique, per_text)
        specs.append(spec)
        budget -= used

    note = ""
    if where:
        note = "  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE %s" % " ".join(where.split())

    return "CREATE %sINDEX IF NOT EXISTS %s ON %s (%s);%s" % (
        "UNIQUE " if unique else "", name, table.name, ", ".join(specs), note)


def translate_expression_index(unique: bool, name: str, table: Table, col_list: list[str]) -> str:
    exprs = [c.strip() for c in col_list]

    # `USING btree ((true))`는 싱글턴 트릭이다. 테이블당 행 하나.
    if len(exprs) == 1 and exprs[0].strip("()").lower() == "true":
        table.add_generated("singleton_key", "singleton_key TINYINT AS (1) VIRTUAL")
        table.add_key(name, "UNIQUE KEY %s (singleton_key)" % name)
        return "-- %s is enforced by the singleton_key generated column on %s" % (name, table.name)

    # `(rule_id, COALESCE(uri_pattern, ''))` — NULL이 유일성을 무력화하면 안 된다.
    # `(lower(name))` — 대소문자 무시 유일성. utf8mb4_bin 콜레이션만으로는 얻을 수
    # 없다.
    specs, gen_cols = [], []
    for expr in exprs:
        lm = re.match(r"^lower\(\s*\(?([A-Za-z_0-9]+)\)?(?:::text)?\s*\)$", expr, re.IGNORECASE)
        if lm:
            src = lm.group(1)
            gen_name = "%s_lower" % src
            src_type = table.column_types.get(src, "VARCHAR(255)")
            gen_type = "VARCHAR(512)" if src_type.split("(")[0].upper() in (
                "TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT") else src_type
            table.add_generated(gen_name, "%s %s AS (LOWER(%s)) VIRTUAL" % (gen_name, gen_type, src))
            gen_cols.append(gen_name)
            specs.append(gen_name)
            continue

        cm = re.match(r"^COALESCE\(\s*([A-Za-z_0-9]+)\s*,\s*''(?:::text)?\s*\)$", expr, re.IGNORECASE)
        if cm:
            src = cm.group(1)
            gen_name = "%s_key" % src
            src_type = table.column_types.get(src, "TEXT")
            gen_type = "VARCHAR(512)" if src_type.split("(")[0].upper() in (
                "TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT") else src_type
            table.add_generated(gen_name, "%s %s AS (COALESCE(%s, '')) VIRTUAL" % (gen_name, gen_type, src))
            gen_cols.append(gen_name)
            specs.append(gen_name)
        else:
            col = expr.strip("()").strip()
            spec, _ = index_column_spec(table, col, unique, 512 * BYTES_PER_CHAR)
            specs.append(spec)

    if gen_cols:
        table.add_key(name, "UNIQUE KEY %s (%s)" % (name, ", ".join(specs)))
        return "-- %s is enforced by generated column(s) %s on %s" % (
            name, ", ".join(gen_cols), table.name)

    return "-- skipped (unsupported expression index): %s" % name


def translate_partial_unique_index(name: str, table: Table, col_list: list[str], where: str) -> str:
    """실제 보장이 WHERE 절에 담겨 있는 UNIQUE 인덱스.

    부분 인덱스는 없지만, 술어 바깥에서 NULL로 평가되는 생성 컬럼이 그 의미를
    정확히 재현한다. 유니크 인덱스는 NULL을 무시하므로 제외된 행은 그냥 참여하지
    않는다.
    """
    cols = [c.strip().strip('"') for c in col_list]
    predicate = " ".join(where.split()).strip("()")
    predicate = re.sub(r"::\s*(?:public\.)?[A-Za-z_0-9]+(\[\])?", "", predicate)
    predicate = predicate.replace(" <> ", " != ")

    gen_name = "%s_key" % name.replace("idx_", "").replace("_unique", "")[:48]
    parts = []
    for c in cols:
        t = table.column_types.get(c, "TEXT").split("(")[0].upper()
        parts.append("COALESCE(CAST(%s AS CHAR), '')" % c if t not in ("VARCHAR", "CHAR") else "COALESCE(%s, '')" % c)
    concat = "CONCAT_WS('\\n', %s)" % ", ".join(parts)

    table.add_generated(gen_name, "%s VARCHAR(768) AS (CASE WHEN %s THEN %s END) VIRTUAL" % (
        gen_name, predicate, concat))
    table.add_key(name, "UNIQUE KEY %s (%s)" % (name, gen_name))
    return "-- %s is enforced by the %s generated column on %s (WHERE %s)" % (
        name, gen_name, table.name, predicate)


# ---------------------------------------------------------------------------
# 렌더링
# ---------------------------------------------------------------------------

MONTH_END = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")


def render_partitions(parent: str, ranges: list[tuple[str, str]]) -> str:
    lines = []
    for child, upper in ranges:
        pname = child.replace("logs_", "").replace("stats_hourly_", "")
        if not pname.startswith("p"):
            pname = "p" + pname
        boundary = upper.split("+")[0].strip()
        lines.append("    PARTITION %s VALUES LESS THAN ('%s')" % (pname, boundary))
    lines.append("    PARTITION p_max VALUES LESS THAN (MAXVALUE)")
    return ",\n".join(lines)


def render_table(table: Table, ranges: dict[str, list[tuple[str, str]]],
                 auto_update: set[str]) -> str:
    lines = []
    for name, mysql_type, tail in table.columns:
        piece = "    %s %s" % (quote_ident(name), mysql_type)
        if tail:
            piece += " " + tail
        # PostgreSQL의 updated_at 트리거는 여기서 컬럼 속성이 된다.
        if name == "updated_at" and table.name in auto_update:
            piece += " ON UPDATE CURRENT_TIMESTAMP(6)"
        lines.append(piece)

    lines.extend("    %s" % g for g in table.generated)
    lines.extend("    %s" % c for c in table.constraints if c)
    lines.extend("    %s" % k for k in table.extra_keys)

    body = ",\n".join(lines)
    options = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"
    if table.name in COMPRESSED_TABLES:
        options += " PAGE_COMPRESSED=1 PAGE_COMPRESSION_LEVEL=%d" % PAGE_COMPRESSION_LEVEL
    out = "CREATE TABLE IF NOT EXISTS %s (\n%s\n) %s" % (table.name, body, options)
    if table.doc:
        out = table.doc + "\n" + out

    if table.partition_by and table.name in ranges:
        out += "\nPARTITION BY RANGE COLUMNS(%s) (\n%s\n)" % (
            table.partition_by, render_partitions(table.name, ranges[table.name]))
    return out + ";"


# MariaDB reserved words that occur, or plausibly could occur, as column names
# in this schema. ANSI_QUOTES is enabled on every connection, so double quotes
# are identifier quotes on both backends and the same DDL parses either way.
RESERVED = {
    "key", "keys", "timestamp", "rows", "row", "groups", "group", "rank", "over",
    "window", "recursive", "system", "lead", "lag", "order", "range", "read",
    "usage", "condition", "interval", "match", "option", "status", "call",
    "signal", "resource", "references", "leave", "release", "purge", "current_role",
}


def quote_ident(name: str) -> str:
    return '"%s"' % name if name.lower() in RESERVED else name


def fix_partitioned_keys(table: Table) -> None:
    """모든 유니크 키는 파티션 컬럼을 포함해야 한다."""
    if not table.partition_by:
        return
    part = table.partition_by

    def add_part(cols: str) -> str:
        names = [c.strip() for c in cols.split(",")]
        if part not in names:
            names.append(part)
        return ", ".join(names)

    new_constraints = []
    for c in table.constraints:
        m = re.match(r"^PRIMARY KEY \((.*)\)$", c)
        if m:
            new_constraints.append("PRIMARY KEY (%s)" % add_part(m.group(1)))
            continue
        m = re.match(r"^UNIQUE KEY (\S*) \((.*)\)$", c)
        if m:
            new_constraints.append("UNIQUE KEY %s (%s)" % (m.group(1), add_part(m.group(2))))
            continue
        # 파티션 테이블은 외래 키에 아예 참여할 수 없다.
        if "FOREIGN KEY" in c.upper():
            continue
        new_constraints.append(c)
    table.constraints = new_constraints

    # 컬럼 수준 PRIMARY KEY/UNIQUE는 두 번째 컬럼을 포함할 수 없다. 승격한다.
    promoted = []
    for i, (name, mysql_type, tail) in enumerate(table.columns):
        if re.search(r"\bPRIMARY KEY\b", tail):
            tail = re.sub(r"\s*\bPRIMARY KEY\b", "", tail).strip()
            promoted.append("PRIMARY KEY (%s, %s)" % (name, part))
        if re.search(r"\bUNIQUE\b", tail):
            tail = re.sub(r"\s*\bUNIQUE\b", "", tail).strip()
            promoted.append("UNIQUE KEY uq_%s_%s (%s, %s)" % (table.name, name, name, part))
        table.columns[i] = (name, mysql_type, tail)
    table.constraints.extend(promoted)


def apply_alter(stmt: str, tables: dict[str, Table]) -> None:
    """지연된 ALTER TABLE 제약을 테이블 정의 안으로 접어 넣는다.

    PostgreSQL 스키마는 pg_dump가 내보내는 방식대로 대부분의 기본 키와 유니크 키를
    사후에 선언한다. ALTER TABLE ADD CONSTRAINT 자체는 받아주지만 키에 대해서는
    IF NOT EXISTS를 붙일 수 없는데, 이 파일은 멱등해야 하므로 제약을 CREATE TABLE
    안으로 옮긴다. 외래 키는 대상이 생기기 전에 실행되면 안 되므로 지연된 채로
    둔다.
    """
    s_ = " ".join(stmt.split())
    m = re.match(
        r"^ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?([A-Za-z_0-9]+)\s+ADD\s+CONSTRAINT\s+"
        r"([A-Za-z_0-9]+)\s+(.*)$", s_, re.IGNORECASE)
    if not m:
        return
    table_name, cname, body = m.groups()
    table = tables.get(table_name)
    if table is None:
        return

    if re.match(r"^PRIMARY\s+KEY", body, re.IGNORECASE):
        cols = normalise_columns(re.search(r"\((.*?)\)", body).group(1))
        if not any(c.startswith("PRIMARY KEY") for c in table.constraints) and not has_inline_pk(table):
            table.constraints.insert(0, "PRIMARY KEY (%s)" % cols)
        return

    if re.match(r"^UNIQUE", body, re.IGNORECASE):
        cols = normalise_columns(re.search(r"\((.*?)\)", body).group(1))
        table.add_key(cname, "UNIQUE KEY %s (%s)" % (cname, cols))
        return

    if re.match(r"^FOREIGN\s+KEY", body, re.IGNORECASE):
        body = re.sub(r"REFERENCES\s+public\.", "REFERENCES ", body, flags=re.IGNORECASE)
        if not any(n == cname for n, _ in table.foreign_keys):
            table.foreign_keys.append((cname, body))
        return

    if re.match(r"^CHECK", body, re.IGNORECASE):
        translated = translate_check(body)
        if translated:
            table.constraints.append("CONSTRAINT %s %s" % (cname, translated))


def has_inline_pk(table: Table) -> bool:
    return any("PRIMARY KEY" in tail for _, _, tail in table.columns)


KEY_CLAUSE_RE = re.compile(r"^(PRIMARY KEY|UNIQUE KEY(?: \S+)?|CONSTRAINT \S+ UNIQUE) \((.*)\)$")


def apply_key_prefixes(table: Table) -> None:
    """모든 키 절을 유효한 형태로 만든다.

    PostgreSQL 원본은 신경 쓸 필요가 없는 두 가지가 있다. InnoDB는 접두사 길이
    없는 TEXT 컬럼을 키에 넣는 것을 거부하고, 예약어를 이름으로 쓴 컬럼은 인용해야
    한다. 인라인·지연·인덱스 유래 키 절을 모두 모은 뒤 여기서 둘 다 적용한다.
    """
    generated_names = {g.split()[0] for g in table.generated}

    def fix(clause: str) -> str:
        m = KEY_CLAUSE_RE.match(clause)
        if not m:
            return clause
        head, cols = m.groups()
        entries = [c.strip() for c in cols.split(",")]

        def is_text(col: str) -> bool:
            return table.column_types.get(col.strip('"'), "").split("(")[0].upper() in (
                "TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT", "JSON")

        # A prefix on a UNIQUE key narrows the guarantee to those first
        # characters, so give text columns as much of the 3072-byte budget as
        # is left after the fixed-width members. MariaDB would otherwise
        # silently switch the whole key to USING HASH and MySQL would reject it
        # outright — neither is what the PostgreSQL constraint says.
        unique = "UNIQUE" in head.upper()
        fixed = sum(type_key_bytes(table.column_types.get(c.strip('"'), "INT"))
                    for c in entries if "(" not in c and not is_text(c))
        text_members = max(1, sum(1 for c in entries if "(" not in c and is_text(c)))
        budget = max(64, (MAX_KEY_BYTES - fixed) // text_members // BYTES_PER_CHAR)
        prefix = min(budget, 768) if unique else TEXT_INDEX_PREFIX

        rendered = []
        for col in entries:
            if "(" in col or col in generated_names:
                rendered.append(col)  # 이미 접두사가 붙었거나 생성 컬럼이다
                continue
            base = col.strip('"')
            if is_text(col):
                rendered.append("%s(%d)" % (quote_ident(base), prefix))
            else:
                rendered.append(quote_ident(base))
        return "%s (%s)" % (head, ", ".join(rendered))

    table.constraints = [fix(c) for c in table.constraints]
    table.extra_keys = [fix(k) for k in table.extra_keys]


def ensure_primary_key(table: Table) -> None:
    """InnoDB에 명시적인 클러스터 키를 준다.

    싱글턴 설정 테이블들(global_waf, cloudflare_tunnel, ...)은 PostgreSQL에서
    기본 키가 없다. 상수 식 `(true)`에 건 유니크 인덱스가 행 하나로 묶어 준다.
    그래도 `id` 컬럼은 실질적으로 유일하므로, 그것을 기본 키로 지정하면 InnoDB가
    보이지 않는 rowid가 아니라 의미 있는 것을 기준으로 클러스터링한다.
    """
    if has_inline_pk(table) or any(c.startswith("PRIMARY KEY") for c in table.constraints):
        return
    if any(name == "id" for name, _, _ in table.columns):
        table.constraints.insert(0, "PRIMARY KEY (id)")


def render_foreign_keys(tables: dict[str, Table]) -> list[str]:
    """모든 테이블이 생긴 뒤에 외래 키를 내보낸다.

    파티션 테이블은 어느 방향으로도 외래 키를 가질 수 없으므로, 조용히 버리지 않고
    건너뛰었다고 표시한다.
    """
    partitioned = {name for name, t in tables.items() if t.partition_by}
    out: list[str] = []
    for name in sorted(tables):
        table = tables[name]
        for cname, body in table.foreign_keys:
            # 원본 파일에는 컬럼이 migration.go의 업그레이드 단계에서야 추가되는
            # 외래 키가 몇 개 있다. 그것들은 신규 설치의 기본 스키마가 아니라
            # 업그레이드 경로에 속한다.
            cols = re.search(r"FOREIGN KEY \(([^)]*)\)", body, re.IGNORECASE)
            if cols and any(c.strip().strip('"') not in table.column_types
                            for c in cols.group(1).split(",")):
                out.append("-- skipped (column added by a later upgrade, not by this file): %s"
                           % cname)
                continue

            target = re.search(r"REFERENCES\s+([A-Za-z_0-9]+)", body, re.IGNORECASE)
            if name in partitioned or (target and target.group(1) in partitioned):
                out.append("-- skipped (%s is partitioned; MariaDB forbids foreign keys there): %s"
                           % (name if name in partitioned else target.group(1), cname))
                continue
            body = re.sub(r"^FOREIGN\s+KEY", "FOREIGN KEY IF NOT EXISTS", body, count=1,
                          flags=re.IGNORECASE)
            out.append("ALTER TABLE %s ADD CONSTRAINT %s %s;" % (name, cname, body))
    return out


def main() -> int:
    sql = SOURCE.read_text()
    prepared = [strip_line_comments(s) for s in split_statements(sql)]
    codes = [code for _, code in prepared]

    enums = parse_enums(codes)
    ranges = parse_partition_ranges(codes)
    tables = parse_tables(prepared, enums)

    auto_update = {
        m.group(1)
        for stmt in codes
        for m in [re.search(r"CREATE\s+TRIGGER\s+\S+\s+BEFORE\s+UPDATE\s+ON\s+(?:public\.)?([A-Za-z_0-9]+)",
                            stmt, re.IGNORECASE)]
        if m
    }

    # 지연된 제약을 먼저 처리한다. 거의 모든 테이블의 기본 키가 이 경로로 오고,
    # 아래 인덱스 단계가 그 존재를 알아야 한다.
    for stmt in codes:
        apply_alter(stmt, tables)

    # 렌더링보다 인덱스를 먼저 번역한다. 식 인덱스와 부분 유니크 규칙이 테이블
    # 정의에 생성 컬럼을 추가하기 때문이다.
    index_lines: list[str] = []
    for stmt in codes:
        if re.match(r"^CREATE\s+(UNIQUE\s+)?INDEX", stmt.strip(), re.IGNORECASE):
            out = translate_index(stmt, tables)
            if out:
                index_lines.append(out)

    for table in tables.values():
        ensure_primary_key(table)
        fix_partitioned_keys(table)
        apply_key_prefixes(table)

    alter_lines = render_foreign_keys(tables)

    parts: list[str] = [HEADER]

    parts.append("-- " + "-" * 74 + "\n-- Tables\n-- " + "-" * 74)
    for name in sorted(tables):
        parts.append(render_table(tables[name], ranges, auto_update))

    parts.append("\n-- " + "-" * 74 + "\n-- Indexes\n-- " + "-" * 74)
    parts.extend(index_lines)

    parts.append("\n-- " + "-" * 74 + "\n-- Foreign keys and deferred constraints\n-- " + "-" * 74)
    parts.extend(alter_lines)

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text("\n".join(parts) + "\n")

    UPGRADES_TARGET.write_text("\n".join(build_upgrades(enums, tables)) + "\n")

    print("wrote %s" % TARGET.relative_to(ROOT))
    print("  tables : %d" % len(tables))
    print("  indexes: %d (%d skipped)" % (
        len([l for l in index_lines if l.startswith("CREATE")]),
        len([l for l in index_lines if l.startswith("--")])))
    print("  alters : %d" % len([l for l in alter_lines if l.startswith("ALTER")]))
    print("  enums  : %s" % ", ".join(sorted(enums)))
    return 0


HEADER = """-- Nginx Proxy Guard — MariaDB/MySQL 초기 스키마
--
-- 생성된 파일입니다. 직접 수정하지 마세요.
-- 원본   : api/internal/database/migrations/001_init.sql (PostgreSQL)
-- 재생성 : python3 scripts/pg2mariadb-schema.py
--
-- 멱등합니다. 모든 객체를 IF NOT EXISTS로 생성합니다.
"""



# ---------------------------------------------------------------------------
# 업그레이드 문장 (migration.go)
#
# 신규 설치에는 001_init.sql만으로 부족하다. migration.go의 업그레이드 목록이
# 컬럼과 테이블, 그리고 결정적으로 PostgreSQL 초기 파일에는 전혀 없는 exploit
# 차단 규칙 시드 행을 추가하기 때문이다. 그 항목들을 여기서 두 번째 파일로
# 번역하고, 러너가 부팅할 때마다 재실행한다. PostgreSQL 경로가 자기 목록을
# 재실행하는 것과 똑같다.
# ---------------------------------------------------------------------------

UPGRADES_SOURCE = ROOT / "api/internal/database/migration.go"
UPGRADES_TARGET = ROOT / "api/internal/database/migrations/mariadb/002_upgrades.sql"

DESC_RE = re.compile(r'desc:\s*"((?:[^"\\]|\\.)*)"\s*,\s*sql:\s*', re.S)


def read_go_string(src: str, pos: int) -> tuple[str, int]:
    """Go 문자열 식을 읽는다. `+` 연결도 따라간다.

    업그레이드 문장 중 몇 개는 백틱을 끼워 넣기 위해 원시 문자열을 중간에 끊는다.
    원시 문자열 안에는 백틱을 넣을 수 없기 때문이다. 백틱으로 둘러싸인 첫 구간만
    읽으면 그런 문장이 리터럴 도중에 잘리고, 실제로 exploit 규칙 시드가 조용히
    누락됐었다.
    """
    parts: list[str] = []
    n = len(src)
    while pos < n:
        while pos < n and src[pos] in " \t\n\r":
            pos += 1
        if pos >= n:
            break
        if src[pos] == "`":
            end = src.index("`", pos + 1)
            parts.append(src[pos + 1:end])
            pos = end + 1
        elif src[pos] == '"':
            j = pos + 1
            buf = []
            while j < n and src[j] != '"':
                if src[j] == "\\":
                    esc = src[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(esc, esc))
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            parts.append("".join(buf))
            pos = j + 1
        else:
            break
        # 명시적인 연결이 있을 때만 이어서 읽는다.
        save = pos
        while pos < n and src[pos] in " \t\n\r":
            pos += 1
        if pos < n and src[pos] == "+":
            pos += 1
            continue
        pos = save
        break
    return "".join(parts), pos


def parse_upgrade_entries(src: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for m in DESC_RE.finditer(src):
        body, _ = read_go_string(src, m.end())
        if body:
            entries.append((m.group(1), body))
    return entries

# PostgreSQL이나 TimescaleDB만을 위해 존재하는 구문들. 이것들을 건너뛰는 것은
# 누락이 아니라 올바른 처리다. 대상 스키마에는 그런 개념 자체가 없거나, 같은
# 보장을 다른 방식으로 표현한다(부분 유니크 인덱스에 대해서는 001_init.sql의
# 생성 컬럼 참고).
POSTGRES_ONLY_MARKERS = (
    "DO $$", "ALTER TYPE", "timescaledb", "pg_inherits", "pg_extension",
    "pg_constraint", "pg_class", "information_schema", "ALTER INDEX",
    "USING gin", "logs_unified", "regclass",
    # DELETE ... USING은 PostgreSQL의 다중 테이블 삭제다. 유일한 쓰임새는 유니크
    # 인덱스보다 먼저 생긴 중복 행을 한 번 정리하는 것인데, 이쪽에서는 그 인덱스가
    # 첫 부팅부터 (생성 컬럼으로) 존재하므로 정리 대상 중복이 생길 수 없다.
    "DELETE FROM dashboard_stats_hourly a",
)


def is_postgres_only(sql: str) -> tuple[bool, str]:
    for marker in POSTGRES_ONLY_MARKERS:
        if marker.lower() in sql.lower():
            return True, marker
    # 술어가 붙은 UNIQUE 인덱스는 힌트가 아니라 제약이다. 001_init.sql이 생성
    # 컬럼으로 대신 재현한다.
    if re.search(r"CREATE\s+UNIQUE\s+INDEX", sql, re.I) and re.search(r"\bWHERE\b", sql, re.I):
        return True, "partial unique index (generated column in 001_init.sql)"
    return False, ""


def convert_column_definition(text: str, enums: dict[str, list[str]]) -> str:
    col = parse_column(text.strip(), enums)
    if not col:
        raise ValueError("cannot parse column definition: %r" % text)
    name, mysql_type, tail, _ = col
    return " ".join(x for x in (quote_ident(name), mysql_type, tail) if x)


def convert_upgrade(sql: str, enums: dict[str, list[str]],
                    tables: dict[str, Table]) -> list[str] | None:
    """업그레이드 문장 하나를 번역한다. 불가능하면 None을 돌려준다."""
    out: list[str] = []
    for stmt in split_statements(sql):
        _, code = strip_line_comments(stmt)
        if not code:
            continue

        m = re.match(r"^ALTER\s+TABLE\s+(?:public\.)?([A-Za-z_0-9]+)\s+ADD\s+COLUMN\s+"
                     r"(?:IF\s+NOT\s+EXISTS\s+)?(.*)$", code, re.I | re.S)
        if m:
            table, definition = m.group(1), m.group(2)
            out.append("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s;" % (
                table, convert_column_definition(definition, enums)))
            continue

        m = re.match(r"^ALTER\s+TABLE\s+(?:public\.)?([A-Za-z_0-9]+)\s+ALTER\s+COLUMN\s+"
                     r"([A-Za-z_0-9]+)\s+SET\s+DEFAULT\s+(.*)$", code, re.I | re.S)
        if m:
            default = map_default(m.group(3), enums)
            if default is None:
                return None
            out.append("ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s;" % (
                m.group(1), quote_ident(m.group(2)), default))
            continue

        m = re.match(r"^ALTER\s+TABLE\s+(?:public\.)?([A-Za-z_0-9]+)\s+"
                     r"DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+([A-Za-z_0-9]+)$", code, re.I)
        if m:
            # 유니크 제약에 대해서는 DROP INDEX로 적는다. 두 형태를 모두
            # 시도하고, 실패는 러너가 감내한다.
            out.append("ALTER TABLE %s DROP INDEX IF EXISTS %s;" % (m.group(1), m.group(2)))
            continue

        if re.match(r"^CREATE\s+TABLE", code, re.I):
            rendered = convert_upgrade_table(code, enums, tables)
            if rendered is None:
                return None
            out.append(rendered)
            continue

        if re.match(r"^CREATE\s+(UNIQUE\s+)?INDEX", code, re.I):
            rendered = translate_index(code, tables)
            if rendered is None or rendered.startswith("--"):
                return None
            out.append(rendered)
            continue

        if re.match(r"^(INSERT|UPDATE|DELETE)\b", code, re.I):
            out.append(convert_dml(code) + ";")
            continue

        return None
    return out


def convert_upgrade_table(code: str, enums: dict[str, list[str]],
                          tables: dict[str, Table]) -> str | None:
    """업그레이드 목록에 나오는 CREATE TABLE을 렌더링한다."""
    parsed = parse_tables([("", code)], enums)
    if not parsed:
        return None
    table = next(iter(parsed.values()))
    ensure_primary_key(table)
    apply_key_prefixes(table)
    # 이후 업그레이드 인덱스가 컬럼 타입을 해석할 수 있도록 등록해 둔다.
    tables.setdefault(table.name, table)

    rendered = render_table(table, {}, set())
    for cname, body in table.foreign_keys:
        body = re.sub(r"^FOREIGN\s+KEY", "FOREIGN KEY IF NOT EXISTS", body, count=1, flags=re.I)
        rendered += "\nALTER TABLE %s ADD CONSTRAINT %s %s;" % (table.name, cname, body)
    return rendered


def convert_dml(code: str) -> str:
    """시드 INSERT나 데이터 보정용 UPDATE/DELETE를 번역한다."""
    out = re.sub(r"\bpublic\.", "", code)

    # ON CONFLICT (id) DO NOTHING -> 아무 일도 하지 않는 자기 대입. 중복 키만
    # 삼키고 나머지는 삼키지 않는다. 이유는 Go 번역기 쪽 설명 참고.
    m = re.search(r"\s+ON\s+CONFLICT\s*\(\s*([A-Za-z_0-9]+)\s*\)\s*DO\s+NOTHING\s*$", out, re.I)
    if m:
        col = m.group(1)
        out = out[:m.start()] + " ON DUPLICATE KEY UPDATE %s = %s" % (col, col)

    out = re.sub(r"\bE'", "'", out)
    out = re.sub(r"::\s*(?:public\.)?[A-Za-z_0-9]+(\[\])?", "", out)
    out = re.sub(r"\bnow\(\)", "CURRENT_TIMESTAMP(6)", out, flags=re.I)
    out = re.sub(r"\bgen_random_uuid\(\)", "UUID()", out, flags=re.I)
    out = re.sub(r"INTERVAL\s+'(\d+)\s+([a-z]+?)s?'",
                 lambda mm: "INTERVAL %s %s" % (mm.group(1), mm.group(2).upper()), out, flags=re.I)
    return out.strip().rstrip(";")


def build_upgrades(enums: dict[str, list[str]], tables: dict[str, Table]) -> list[str]:
    src = UPGRADES_SOURCE.read_text()
    entries = parse_upgrade_entries(src)
    if not entries:
        raise SystemExit("no upgrade entries parsed from migration.go — has its shape changed?")

    lines = [UPGRADES_HEADER]
    applied = skipped = 0
    for desc, sql in entries:
        postgres_only, marker = is_postgres_only(sql)
        if postgres_only:
            lines.append("-- skipped (%s): %s" % (marker, desc))
            skipped += 1
            continue
        try:
            rendered = convert_upgrade(sql, enums, tables)
        except (ValueError, SystemExit):
            rendered = None
        if rendered is None:
            lines.append("-- skipped (no mechanical translation): %s" % desc)
            skipped += 1
            continue
        lines.append("-- %s" % desc)
        lines.extend(rendered)
        applied += 1

    print("  upgrades: %d translated, %d skipped" % (applied, skipped))
    return lines


UPGRADES_HEADER = """-- Nginx Proxy Guard — MariaDB/MySQL 업그레이드 문장
--
-- 생성된 파일입니다. 직접 수정하지 마세요.
-- 원본   : api/internal/database/migration.go (`upgrades` 슬라이스)
-- 재생성 : python3 scripts/pg2mariadb-schema.py
--
-- Replayed on every boot, like its PostgreSQL counterpart: every statement is
-- idempotent, and the runner logs rather than aborts when one fails.
"""


if __name__ == "__main__":
    sys.exit(main())
