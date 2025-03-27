from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import re
from flask_cors import CORS
from contextlib import contextmanager
import logging
import json  # 添加 json 模块导入

app = Flask(__name__)
CORS(app)  # 启用 CORS
app.logger.setLevel(logging.DEBUG)

# 数据库连接上下文管理器
@contextmanager
def get_db_connection():
    conn = sqlite3.connect('library.db')
    try:
        yield conn
    finally:
        conn.close()

# 验证邮箱格式
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email)

# 创建数据库表
def create_table():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 创建读者表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS readers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id TEXT NOT NULL UNIQUE,
            customer_name TEXT NOT NULL,
            gender TEXT NOT NULL,
            id_number TEXT NOT NULL UNIQUE,
            contact_phone TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE
        )
        ''')
        # 修改用户表结构
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_locked INTEGER DEFAULT 0,
            role_id INTEGER,
            FOREIGN KEY (role_id) REFERENCES permissions(id)
        )
        ''')
        cursor.execute('''
                CREATE TABLE IF NOT EXISTS permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    role_name TEXT NOT NULL UNIQUE,
                    accessible_menus TEXT
                )
            ''')
        # 创建菜单表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS menus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            menu_name TEXT NOT NULL UNIQUE
        )
        ''')
        conn.commit()
        conn.close()

# 调用函数创建表
create_table()

# 注册接口
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "请求数据格式不正确"}), 400
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password:
        return jsonify({"success": False, "message": "缺少必要参数"}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # 生成盐
            salt = bcrypt.gensalt()
            # 对密码进行哈希处理
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            cursor.execute('INSERT INTO users (username, password) VALUES (?,?)',
                           (username, hashed_password))
            conn.commit()
            response = jsonify({"success": True, "message": "注册成功", "redirect": "Login page.html"}), 201
            app.logger.info(f"注册接口返回报文: {response[0].get_json()}")
            return response
    except sqlite3.IntegrityError:
        response = jsonify({"success": False, "message": "该用户名已被使用，请选择其他用户名"}), 400
        app.logger.info(f"注册接口返回报文: {response[0].get_json()}")
        return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"注册接口返回报文: {response[0].get_json()}")
        return response
    except Exception as e:
        app.logger.error(f"其他错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"注册接口返回报文: {response[0].get_json()}")
        return response

# 登录接口
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "用户名和密码不能为空"}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password, role_id FROM users WHERE username =?', (username,))
            user = cursor.fetchone()
            if user:
                stored_password = user[1]
                if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                    # 获取用户角色
                    role_id = user[2]
                    if role_id:
                        cursor.execute('SELECT accessible_menus FROM permissions WHERE id =?', (role_id,))
                        role = cursor.fetchone()
                        # 将 accessible_menus 转换为数字数组
                        accessible_menus = json.loads(role[0]) if role else []  # 解析 JSON 字符串为数组
                        accessible_menus = [int(item) for item in accessible_menus]  # 将数组中的字符串转换为数字
                    else:
                        accessible_menus = []
                    response = jsonify({
                        "success": True,
                        "message": "登录成功",
                        "redirect": "Main interface.html",
                        "accessible_menus": accessible_menus  # 返回数字数组
                    }), 200
                    return response
            return jsonify({"success": False, "message": "用户名或密码错误"}), 401
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": str(e)}), 500

# 添加读者的接口
@app.route('/create_customer', methods=['POST'])
def create_customer():
    data = request.get_json()
    customer_id = data.get('customer_id')
    customer_name = data.get('customer_name')
    gender = data.get('gender')
    id_number = data.get('id_number')
    contact_phone = data.get('contact_phone')
    email = data.get('email')

    if not all([customer_id, customer_name, gender, id_number, contact_phone, email]):
        missing_fields = [field for field, value in data.items() if not value]
        app.logger.error(f"请求缺少必填字段: {missing_fields}")
        response = jsonify({"success": False, "message": "请填写完整所有必填项"}), 400
        app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
        return response

    try:
        with get_db_connection() as conn:
            conn.isolation_level = 'IMMEDIATE'  # 设置隔离级别
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO readers (customer_id, customer_name, gender, id_number, contact_phone, email)
            VALUES (?,?,?,?,?,?)
            ''', (customer_id, customer_name, gender, id_number, contact_phone, email))
            conn.commit()
            response = jsonify({"success": True, "message": "读者添加成功"}), 201
            app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
            return response
    except sqlite3.IntegrityError as e:
        if 'UNIQUE constraint failed: readers.email' in str(e):
            response = jsonify({"success": False, "message": "该电子邮箱地址已被使用，请使用其他邮箱地址。"}), 400
            app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
            return response
        elif 'UNIQUE constraint failed: readers.customer_id' in str(e):
            response = jsonify({"success": False, "message": "该客户号已被使用，请使用其他客户号。"}), 400
            app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
            return response
        elif 'UNIQUE constraint failed: readers.id_number' in str(e):
            response = jsonify({"success": False, "message": "该身份证号码已被使用，请检查输入。"}), 400
            app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
            return response
        else:
            app.logger.error(f"SQLite 完整性错误: {e}")
            response = jsonify({"success": False, "message": str(e)}), 500
            app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
            return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
        return response
    except Exception as e:
        app.logger.error(f"其他错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"添加读者接口返回报文: {response[0].get_json()}")
        return response

# 获取读者列表的接口
@app.route('/get_readers', methods=['GET'])
def get_readers():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            search_name = request.args.get('name')
            search_customer_id = request.args.get('customer_id')
            search_id_number = request.args.get('id_number')

            query = 'SELECT customer_id, customer_name, gender, id_number, contact_phone, email FROM readers'
            conditions = []
            params = []

            if search_name:
                conditions.append('customer_name LIKE?')
                params.append(f'%{search_name}%')
            if search_customer_id:
                conditions.append('customer_id LIKE?')
                params.append(f'%{search_customer_id}%')
            if search_id_number:
                conditions.append('id_number LIKE?')
                params.append(f'%{search_id_number}%')

            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)

            cursor.execute(query, params)
            readers = cursor.fetchall()
            reader_list = []
            for reader in readers:
                reader_dict = {
                    'customer_id': reader[0],
                    'customer_name': reader[1],
                    'gender': reader[2],
                    'id_number': reader[3],
                    'contact_phone': reader[4],
                    'email': reader[5]
                }
                reader_list.append(reader_dict)

            response = jsonify({
                'readers': reader_list
            })
            app.logger.info(f"获取读者列表接口返回报文: {response.get_json()}")
            return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"获取读者列表接口返回报文: {response[0].get_json()}")
        return response

# 获取单个读者信息的接口
@app.route('/get_reader/<customer_id>', methods=['GET'])
def get_reader(customer_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT customer_id, customer_name, gender, id_number, contact_phone, email FROM readers WHERE customer_id =?', (customer_id,))
            reader = cursor.fetchone()
            if reader:
                reader_dict = {
                    'customer_id': reader[0],
                    'customer_name': reader[1],
                    'gender': reader[2],
                    'id_number': reader[3],
                    'contact_phone': reader[4],
                    'email': reader[5]
                }
                response = jsonify(reader_dict)
                app.logger.info(f"获取单个读者信息接口返回报文: {response.get_json()}")
                return response
            else:
                response = jsonify({"success": False, "message": "未找到该读者信息"}), 404
                app.logger.info(f"获取单个读者信息接口返回报文: {response[0].get_json()}")
                return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"获取单个读者信息接口返回报文: {response[0].get_json()}")
        return response

# 修改读者信息的接口
@app.route('/update_reader/<customer_id>', methods=['PUT'])
def update_reader(customer_id):
    data = request.get_json()
    customer_name = data.get('customer_name')
    gender = data.get('gender')
    id_number = data.get('id_number')
    contact_phone = data.get('contact_phone')
    email = data.get('email')

    if not all([customer_name, gender, id_number, contact_phone, email]):
        missing_fields = [field for field, value in data.items() if not value]
        app.logger.error(f"请求缺少必填字段: {missing_fields}")
        response = jsonify({"success": False, "message": "请填写完整所有必填项"}), 400
        app.logger.info(f"修改读者信息接口返回报文: {response[0].get_json()}")
        return response

    try:
        with get_db_connection() as conn:
            conn.isolation_level = 'IMMEDIATE'  # 设置隔离级别
            cursor = conn.cursor()
            cursor.execute('''
            UPDATE readers
            SET customer_name =?, gender =?, id_number =?, contact_phone =?, email =?
            WHERE customer_id =?
            ''', (customer_name, gender, id_number, contact_phone, email, customer_id))
            conn.commit()
            if cursor.rowcount > 0:
                response = jsonify({"success": True, "message": "读者信息修改成功"})
                app.logger.info(f"修改读者信息接口返回报文: {response.get_json()}")
                return response
            else:
                response = jsonify({"success": False, "message": "未找到该读者信息"}), 404
                app.logger.info(f"修改读者信息接口返回报文: {response[0].get_json()}")
                return response
    except sqlite3.IntegrityError as e:
        if 'UNIQUE constraint failed: readers.email' in str(e):
            response = jsonify({"success": False, "message": "该电子邮箱地址已被使用，请使用其他邮箱地址。"}), 400
            app.logger.info(f"修改读者信息接口返回报文: {response[0].get_json()}")
            return response
        elif 'UNIQUE constraint failed: readers.id_number' in str(e):
            response = jsonify({"success": False, "message": "该身份证号码已被使用，请检查输入。"}), 400
            app.logger.info(f"修改读者信息接口返回报文: {response[0].get_json()}")
            return response
        else:
            app.logger.error(f"SQLite 完整性错误: {e}")
            response = jsonify({"success": False, "message": str(e)}), 500
            app.logger.info(f"修改读者信息接口返回报文: {response[0].get_json()}")
            return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"修改读者信息接口返回报文: {response[0].get_json()}")
        return response
    except Exception as e:
        app.logger.error(f"其他错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"修改读者信息接口返回报文: {response[0].get_json()}")
        return response

# 删除读者信息的接口
@app.route('/delete_reader/<customer_id>', methods=['DELETE'])
def delete_reader(customer_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM readers WHERE customer_id =?', (customer_id,))
            conn.commit()
            if cursor.rowcount > 0:
                response = jsonify({"success": True, "message": "读者信息删除成功"})
                app.logger.info(f"删除读者信息接口返回报文: {response.get_json()}")
                return response
            else:
                response = jsonify({"success": False, "message": "未找到该读者信息"}), 404
                app.logger.info(f"删除读者信息接口返回报文: {response[0].get_json()}")
                return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"删除读者信息接口返回报文: {response[0].get_json()}")
        return response

# 修改获取用户列表接口
@app.route('/get_users', methods=['GET'])
def get_users():
    try:
        conn = sqlite3.connect('library.db')
        cursor = conn.cursor()
        search_username = request.args.get('username')

        query = 'SELECT users.id, users.username, permissions.role_name FROM users LEFT JOIN permissions ON users.role_id = permissions.id'
        conditions = []
        params = []

        if search_username:
            conditions.append('users.username LIKE?')
            params.append(f'%{search_username}%')

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        cursor.execute(query, params)
        users = cursor.fetchall()
        user_list = []
        for user in users:
            user_dict = {
                'id': user[0],
                'username': user[1],
                'role_name': user[2]
            }
            user_list.append(user_dict)

        response = jsonify({
            'users': user_list
        })
        app.logger.info(f"获取用户列表接口返回报文: {response.get_json()}")
        return response
    except sqlite3.Error as e:
        print(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"获取用户列表接口返回报文: {response[0].get_json()}")
        return response

# 锁定用户
@app.route('/lock_user/<user_id>', methods=['PUT'])
def lock_user(user_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_locked = 1 WHERE id =?', (user_id,))
            conn.commit()
            if cursor.rowcount > 0:
                response = jsonify({"success": True, "message": "用户锁定成功"})
                app.logger.info(f"锁定用户接口返回报文: {response.get_json()}")
                return response
            else:
                response = jsonify({"success": False, "message": "未找到该用户信息"}), 404
                app.logger.info(f"锁定用户接口返回报文: {response[0].get_json()}")
                return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"锁定用户接口返回报文: {response[0].get_json()}")
        return response

# 解锁用户
@app.route('/unlock_user/<user_id>', methods=['PUT'])
def unlock_user(user_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_locked = 0 WHERE id =?', (user_id,))
            conn.commit()
            if cursor.rowcount > 0:
                response = jsonify({"success": True, "message": "用户解锁成功"})
                app.logger.info(f"解锁用户接口返回报文: {response.get_json()}")
                return response
            else:
                response = jsonify({"success": False, "message": "未找到该用户信息"}), 404
                app.logger.info(f"解锁用户接口返回报文: {response[0].get_json()}")
                return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"解锁用户接口返回报文: {response[0].get_json()}")
        return response

# 重置密码
@app.route('/reset_password/<user_id>', methods=['PUT'])
def reset_password(user_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # 这里简单将密码重置为默认值，实际应用中需要根据需求修改
            new_password = '123456'
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
            cursor.execute('UPDATE users SET password =? WHERE id =?', (hashed_password, user_id))
            conn.commit()
            if cursor.rowcount > 0:
                response = jsonify({"success": True, "message": "用户密码重置成功"})
                app.logger.info(f"重置密码接口返回报文: {response.get_json()}")
                return response
            else:
                response = jsonify({"success": False, "message": "未找到该用户信息"}), 404
                app.logger.info(f"重置密码接口返回报文: {response[0].get_json()}")
                return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"重置密码接口返回报文: {response[0].get_json()}")
        return response

# 删除用户
@app.route('/delete_user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id =?', (user_id,))
            conn.commit()
            if cursor.rowcount > 0:
                response = jsonify({"success": True, "message": "用户删除成功"})
                app.logger.info(f"删除用户接口返回报文: {response.get_json()}")
                return response
            else:
                response = jsonify({"success": False, "message": "未找到该用户信息"}), 404
                app.logger.info(f"删除用户接口返回报文: {response[0].get_json()}")
                return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"删除用户接口返回报文: {response[0].get_json()}")
        return response

# 获取权限列表
@app.route('/get_permissions', methods=['GET'])
def get_permissions():
    try:
        role_name = request.args.get('role_name')
        conn = sqlite3.connect('library.db')
        cursor = conn.cursor()
        if role_name:
            cursor.execute('SELECT id, role_name, accessible_menus FROM permissions WHERE role_name LIKE ?', ('%' + role_name + '%',))
        else:
            cursor.execute('SELECT id, role_name, accessible_menus FROM permissions')
        permissions = cursor.fetchall()
        result = []
        for permission in permissions:
            id, role_name, accessible_menus = permission
            accessible_menus = json.loads(accessible_menus) if accessible_menus else []  # 将 JSON 字符串解析为数组
            result.append({
                'id': id,
                'role_name': role_name,
                'accessible_menus': accessible_menus  # 返回数组
            })
        conn.close()
        response = jsonify({'permissions': result})
        app.logger.info(f"获取权限列表接口返回报文: {response.get_json()}")
        return response
    except Exception as e:
        response = jsonify({'success': False, 'message': str(e)}), 500
        app.logger.info(f"获取权限列表接口返回报文: {response[0].get_json()}")
        return response

# 新增权限
@app.route('/add_permission', methods=['POST'])
def add_permission():
    try:
        data = request.get_json()
        role_name = data.get('role_name')
        accessible_menus = data.get('accessible_menus', [])  # 获取所有可访问的菜单项
        accessible_menus_json = json.dumps(accessible_menus)  # 将菜单项转换为 JSON 字符串
        conn = sqlite3.connect('library.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO permissions (role_name, accessible_menus) VALUES (?,?)', (role_name, accessible_menus_json))
            conn.commit()
            response = jsonify({'success': True, 'message': '权限新增成功'})
            app.logger.info(f"新增权限接口返回报文: {response.get_json()}")
            return response
        except sqlite3.IntegrityError:
            response = jsonify({'success': False, 'message': '角色名称已存在，请使用其他名称'}), 400
            app.logger.info(f"新增权限接口返回报文: {response[0].get_json()}")
            return response
    except Exception as e:
        response = jsonify({'success': False, 'message': str(e)}), 500
        app.logger.info(f"新增权限接口返回报文: {response[0].get_json()}")
        return response
    finally:
        if conn:
            conn.close()

# 获取单个权限信息
@app.route('/get_permission/<int:role_id>', methods=['GET'])
def get_permission(role_id):
    try:
        conn = sqlite3.connect('library.db')
        cursor = conn.cursor()
        cursor.execute('SELECT role_name, accessible_menus FROM permissions WHERE id =?', (role_id,))
        permission = cursor.fetchone()
        if permission:
            role_name, accessible_menus = permission
            accessible_menus = json.loads(accessible_menus) if accessible_menus else []
            response = jsonify({
                'role_name': role_name,
                'accessible_menus': accessible_menus
            })
            app.logger.info(f"获取单个权限信息接口返回报文: {response.get_json()}")
            return response
        else:
            response = jsonify({'success': False, 'message': '未找到该权限记录'}), 404
            app.logger.info(f"获取单个权限信息接口返回报文: {response[0].get_json()}")
            return response
    except Exception as e:
        response = jsonify({'success': False, 'message': str(e)}), 500
        app.logger.info(f"获取单个权限信息接口返回报文: {response[0].get_json()}")
        return response
    finally:
        if conn:
            conn.close()

# 修改权限
@app.route('/update_permission/<int:role_id>', methods=['PUT'])
def update_permission(role_id):
    try:
        data = request.get_json()
        accessible_menus = data.get('accessible_menus', [])
        accessible_menus_json = json.dumps(accessible_menus)  # 将数组转换为 JSON 字符串
        conn = sqlite3.connect('library.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE permissions SET accessible_menus =? WHERE id =?', (accessible_menus_json, role_id))
        if cursor.rowcount == 0:
            response = jsonify({'success': False, 'message': '未找到该权限记录'}), 404
            app.logger.info(f"修改权限接口返回报文: {response[0].get_json()}")
            return response
        conn.commit()
        response = jsonify({'success': True, 'message': '权限修改成功'})
        app.logger.info(f"修改权限接口返回报文: {response.get_json()}")
        return response
    except Exception as e:
        response = jsonify({'success': False, 'message': str(e)}), 500
        app.logger.info(f"修改权限接口返回报文: {response[0].get_json()}")
        return response
    finally:
        if conn:
            conn.close()

# 删除权限
@app.route('/delete_permission/<int:role_id>', methods=['DELETE'])
def delete_permission(role_id):
    try:
        conn = sqlite3.connect('library.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM permissions WHERE id =?', (role_id,))
        if cursor.rowcount == 0:
            response = jsonify({'success': False, 'message': '未找到该权限记录'}), 404
            app.logger.info(f"删除权限接口返回报文: {response[0].get_json()}")
            return response
        conn.commit()
        response = jsonify({'success': True, 'message': '权限删除成功'})
        app.logger.info(f"删除权限接口返回报文: {response.get_json()}")
        return response
    except Exception as e:
        response = jsonify({'success': False, 'message': str(e)}), 500
        app.logger.info(f"删除权限接口返回报文: {response[0].get_json()}")
        return response
    finally:
        if conn:
            conn.close()

# 分配角色接口
@app.route('/assign_role', methods=['POST'])
def assign_role():
    data = request.get_json()
    user_id = data.get('user_id')
    role_id = data.get('role_id')

    if not user_id or not role_id:
        response = jsonify({"success": False, "message": "用户ID和角色ID不能为空"}), 400
        app.logger.info(f"分配角色接口返回报文: {response[0].get_json()}")
        return response

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # 检查用户和角色是否存在
            cursor.execute('SELECT id FROM users WHERE id =?', (user_id,))
            user = cursor.fetchone()
            if not user:
                response = jsonify({"success": False, "message": "用户不存在"}), 404
                app.logger.info(f"分配角色接口返回报文: {response[0].get_json()}")
                return response

            cursor.execute('SELECT id FROM permissions WHERE id =?', (role_id,))
            role = cursor.fetchone()
            if not role:
                response = jsonify({"success": False, "message": "角色不存在"}), 404
                app.logger.info(f"分配角色接口返回报文: {response[0].get_json()}")
                return response

            # 更新用户的角色
            cursor.execute('UPDATE users SET role_id =? WHERE id =?', (role_id, user_id))
            conn.commit()
            response = jsonify({"success": True, "message": "角色分配成功"}), 200
            app.logger.info(f"分配角色接口返回报文: {response[0].get_json()}")
            return response
    except sqlite3.Error as e:
        app.logger.error(f"SQLite 错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"分配角色接口返回报文: {response[0].get_json()}")
        return response
    except Exception as e:
        app.logger.error(f"其他错误: {e}")
        response = jsonify({"success": False, "message": str(e)}), 500
        app.logger.info(f"分配角色接口返回报文: {response[0].get_json()}")
        return response

if __name__ == '__main__':
    app.run(debug=True)