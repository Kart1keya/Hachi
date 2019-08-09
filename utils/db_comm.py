import sqlite3
from config import Config


opts = Config().read_config()


def insert(uid, hash, filename, status):
    conn = sqlite3.connect(opts["config"]["DB_PATH"])
    conn.execute("""INSERT INTO HACHI (UID,HASH,FILEPATH, STATUS) VALUES (?, ?, ?, ? );""", (uid, hash, filename, status))
    conn.commit()
    conn.close()


def get_data():
    conn = sqlite3.connect(opts["config"]["DB_PATH"])
    cursor = conn.execute("SELECT uid, filepath, status from HACHI")
    data = []
    for row in cursor:
        data.append(row)
    conn.close()
    return data


def update(uid, value):
    conn = sqlite3.connect(opts["config"]["DB_PATH"])
    conn.execute("""UPDATE HACHI SET STATUS = ? where UID = ?;""", (value, uid))
    conn.commit()
    conn.close()


def count(column_name):
    conn = sqlite3.connect(opts["config"]["DB_PATH"])
    cursor = conn.execute("""SELECT COUNT(?) from HACHI;""", (column_name,))
    value = cursor.fetchone()[0]
    conn.close()
    return value


def count_condition(column_name, cond_coulmn_name, value):
    conn = sqlite3.connect(opts["config"]["DB_PATH"])
    q = """SELECT COUNT(%s) FROM HACHI WHERE %s = "%s";""" %(column_name, cond_coulmn_name, value)
    cursor = conn.execute(q)
    value = cursor.fetchone()[0]
    conn.close()
    return value


def get_column_val(uid_column, uid, column_name):
    conn = sqlite3.connect(opts["config"]["DB_PATH"])
    q = """SELECT %s FROM HACHI WHERE %s = "%s";""" % (column_name, uid_column, uid)
    cursor = conn.execute(q)
    value = cursor.fetchone()[0]
    conn.close()
    return value


def create_table():
    conn = sqlite3.connect(opts["config"]["DB_PATH"])
    conn.execute('''CREATE TABLE HACHI
             (UID CHAR(50) PRIMARY KEY     NOT NULL,
             hash           CHAR(50),
             filepath       CHAR(50),
             status        TEXT,
             timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);''')
    conn.close()

