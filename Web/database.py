import mysql
import mysql.connector


def get_mysql_connection():
    cnx = mysql.connector.connect(user='th000', password='Nt#9t=Lmwcbw',
                                  host='59.110.162.232', database='chatdb',
                                  port='3306')
    return cnx