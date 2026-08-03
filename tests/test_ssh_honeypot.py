import sys, sqlite3, os, tempfile
sys.path.insert(0, ".")

def test_db_schema():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dbpath = f.name
    conn = sqlite3.connect(dbpath)
    conn.execute("CREATE TABLE IF NOT EXISTS attempts (ts,ip,username,password,country,city,asn)")
    conn.execute("INSERT INTO attempts VALUES (?,?,?,?,?,?,?)",
                ("2025-08-01T10:00:00","1.2.3.4","admin","password","US","NYC","AS1234"))
    conn.commit()
    row = conn.execute("SELECT * FROM attempts WHERE ip=?", ("1.2.3.4",)).fetchone()
    assert row is not None
    assert row[2] == "admin"
    conn.close()
    os.unlink(dbpath)

def test_stats_query():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dbpath = f.name
    conn = sqlite3.connect(dbpath)
    conn.execute("CREATE TABLE IF NOT EXISTS attempts (ts,ip,username,password,country,city,asn)")
    for i in range(5):
        conn.execute("INSERT INTO attempts VALUES (?,?,?,?,?,?,?)",
                    (f"2025-08-0{i+1}","10.0.0.1","root","123456","RU","Moscow","AS12345"))
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM attempts WHERE ip=?", ("10.0.0.1",)).fetchone()[0]
    assert count == 5
    conn.close()
    os.unlink(dbpath)

if __name__ == "__main__":
    test_db_schema()
    test_stats_query()
    print("All tests passed.")
