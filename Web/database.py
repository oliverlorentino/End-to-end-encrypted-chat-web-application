import mysql
import mysql.connector


def get_mysql_connection():
    cnx = mysql.connector.connect(user='developer0414', password='QRHqrh13927485@',
                                  host='59.110.162.232', database='chatdb',
                                  port='3306')
    return cnx