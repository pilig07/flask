from .entities.User import User

class ModelUser():

    @classmethod
    def login(self,db,user):
        try:
            cursor = db.connection.cursor()
            sql ="""SELECT id, username, password, fullname FROM usuarios WHERE username = '{}'""".format(user.username)
            cursor.execute(sql)
            row = cursor.fetchone()
            if row != None:
                user = User(row[0],row[1],User.check_password(row[2],user.password),row[3])
                return user
        except Exception as e:
            raise Exception(e)

    @classmethod
    def get_by_id(self,db,id):
        try:
            cursor = db.connection.cursor()
            sql ="SELECT id, username, fullname,password FROM usuarios WHERE id = {}".format(id)
            cursor.execute(sql)
            row = cursor.fetchone()
            if row != None:
                return User(row[0],row[1],None,row[2])
        except Exception as e:
            raise Exception(e)