from flask_restful import Resource
from flask import request
import mysql.connector
from mysql.connector import Error

from mysql_connection import get_connection

from email_validator import validate_email, EmailNotValidError

from resources.utll import check_password, hash_password

from flask_jwt_extended import create_access_token, get_jwt, jwt_required

import datetime

class UserRegisterResource(Resource):
    
    def post(self):

        # {
        #     "username": "홍길동",
        #     "email": "abc@naver.com",
        #     "password": "1234"
        # }

        # 1. 클라이언트가 보낸 데이터를 받아준다

        data = request.get_json()

        # 2. email 주소 형식이 올바른지 확인한다
        try:
            validate_email( data['email'] )
        except EmailNotValidError as e :
            print(e)
            return {'result' : 'fail', 'error' : str(e)}, 400

        # 3. 비밀번호 길이가 유효한 지 확인한다
        
        #  만약 비밀번호가 4자리 이상, 12자리 이하라고 한다면
        if len( data['password'] ) < 4 or len( data['password'] ) > 12:
            return {'result' : 'fail', 'error' : '비밀번호는 4자리 이상 12자리 이하로 만들어주세요'}, 400      

        # 4. 비밀번호를 암호화 한다
        hashed_password = hash_password(data['password'])
        print(hashed_password)

        # 5. DB에 회원정보가 있는지 확인을 한다
        try:
            connection = get_connection()
            query = '''select *
                    from user
                    where email = %s;'''
            record = ( data['email'] , )

            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, record)
            
            result_list = cursor.fetchall()

            print(result_list)

            if len(result_list) == 1 :
                return  {'result' : 'fail', 'error' : ' 이미 가입을 하셨습니다'}, 400

            # 위의 코드는 회원이 가입여부를 확인하기 위한 코드
            # 아래부터는 회원가입을 위한 코드를 작성하여 DB에 저장한다
            query = '''insert into user
                    (username, email, password)
                    values
                    (%s, %s, %s);'''
            record = (data['username'],
                      data['email'],
                      hashed_password)
            cursor = connection.cursor()
            cursor.execute(query, record)

            connection.commit()

            ### DB에 데이터를 insert 한 후 insert된 행의 아이디를 가져오는 코드
            user_id = cursor.lastrowid

            cursor.close()
            connection.close()

        except Error as e:
            print(e)
            return  {'result' : 'fail', 'error' : str(e)}, 500
        
        # create_access_token(user_id, expires_delta=datetime.timedelta(days=10))
        access_token = create_access_token(user_id)

        return {'result' : 'success', 'access_token': access_token}

### 로그인 관련 개발

#클래스를 지정
class UserLoginResource(Resource):
    def post(self):
        # 1. 클라이언트로부터 데이터를 받아온다
        data = request.get_json()

        # 2. 이메일 주소로 DB에 select 한다
        try:            
            connection = get_connection()
            query = '''select *
                    from user
                    where email = %s;'''
            record = (data['email'] , )

            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, record)

            result_list = cursor.fetchall()
           
            cursor.close()
            connection.close()
            
        except Error as e:
            print(e)
            return {'result':'fail', 'error':str(e)}, 500
        
        if len(result_list) == 0:
                return {'result':'fail','error':'회원가입이 되어있지 않습니다'}, 400
           
        # 3. 비밀번호가 일치하는지 확인한다
        # 암호화된 비밀번호가 일치하는지 확인해야한다
        print(result_list)
        
        check = check_password(data['password'], result_list[0]['password'])
        if check == False:
            return {'result':'fail', 'error':'비밀번호가 틀렸습니다'}, 400


        # 4. 클라이언트에게 데이터를 보내준다
        access_token = create_access_token(result_list[0]['id'])

        return {'result':'success', 'access_token' : access_token }
    

#### 로그아웃 관련 개발
# 로그아웃 토큰을 저장할 set를 만든다

jwt_blocklist = set()

class UserLogoutResource(Resource):
    
    @jwt_required()
    def delete(self):

        jti = get_jwt()['jti']
        print(jti)
        jwt_blocklist.add(jti)
        
        return {'result':'sucess'}
















