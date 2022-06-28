from app import db, User

username = "doni"
password = "doni123"

level = "Administrasi"

mydata = User(username, password, level)
db.session.add(mydata)
db.session.commit()