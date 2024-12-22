import networkx as nx
import matplotlib.pyplot as plt
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import time
import json

app = Flask(__name__)

# Конфігурація додатка
DATABASE_SQL = 'database.db'  # Для перевірки SQL-запитів
DATABASE_USERS = 'users.db'   # Для збереження даних користувачів


# Функція для отримання з'єднання з базою даних
def get_db_connection(database):
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    return conn


# Створення бази даних користувачів
def create_users_db():
    conn = get_db_connection(DATABASE_USERS)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


# Ініціалізація бази даних
create_users_db()

# Функція для очищення бази даних
def clear_database():
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    # Отримуємо список усіх таблиць, крім системної таблиці sqlite_sequence
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';")
    tables = cursor.fetchall()

    # Видаляємо всі таблиці
    for table_name, in tables:
        cursor.execute(f"DROP TABLE IF EXISTS {table_name};")

    connection.commit()
    connection.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/main')
def main():
    return render_template('main.html')

# Сторінка входу
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection(DATABASE_USERS)

        # Отримуємо користувача за логіном
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):  # Перевірка хешу пароля
            session['user_id'] = user['id']  # Зберігаємо ID користувача
            session['username'] = user['username']  # Зберігаємо ім'я користувача
            return redirect(url_for('main'))
        else:
            flash('Невірний логін або пароль', 'error')
    return render_template('login.html')


# Функція для перевірки складності пароля
def validate_password(password):
    if len(password) < 8:
        flash("Пароль має бути не менше 8 символів.", "error")
        return False
    if not re.search("[A-Z]", password):
        flash("Пароль має містити хоча б одну велику літеру.", "error")
        return False
    if not re.search("[a-z]", password):
        flash("Пароль має містити хоча б одну малу літеру.", "error")
        return False
    if not re.search("[0-9]", password):
        flash("Пароль має містити хоча б одну цифру.", "error")
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        flash("Пароль має містити хоча б один спеціальний символ.", "error")
        return False
    return True


# Функція для перевірки збігу паролів
def validate_passwords_match(password, confirm_password):
    if password != confirm_password:
        flash("Паролі не збігаються.", "error")
        return False
    return True


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Перевірка на унікальність логіну
        conn = get_db_connection(DATABASE_USERS)
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            flash('Користувач з таким логіном вже існує.', 'error')
            conn.close()
            return render_template('register.html', username=username, password=password,
                                   confirm_password=confirm_password)

        # Перевірка на співпадіння паролів
        if password != confirm_password:
            flash('Паролі не співпадають.', 'error')
            conn.close()
            return render_template('register.html', username=username, password='', confirm_password='')

        # Хешування пароля
        hashed_password = generate_password_hash(password)

        # Збереження нового користувача
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Реєстрація успішна! Тепер ви можете увійти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Користувач з таким логіном вже існує.', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/check_username', methods=['GET'])
def check_username():
    username = request.args.get('username')
    if not username:
        return jsonify({'exists': False})

    conn = get_db_connection(DATABASE_USERS)
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if user:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})


# Вихід із системи
@app.route('/logout')
def logout():
    # Очистити всі дані сесії
    session.clear()

    # Перенаправлення на головну сторінку
    return redirect(url_for('index'))


import re

@app.route('/get_optimization_tips', methods=['POST'])
def get_optimization_tips():
    data = request.get_json()  # Отримуємо JSON-запит
    sql_query = data.get('sql_query')  # Отримуємо sql_query з JSON

    if not sql_query:
        return jsonify({"error": "sql_query parameter is missing"}), 400

    tips = []

    # 1. Перевірка на використання SELECT *
    if re.search(r"SELECT \*", sql_query, re.IGNORECASE):
        tips.append("Уникайте використання 'SELECT *'. Зазначте лише необхідні стовпці.")

    # 2. Перевірка на відсутність індексів у великих таблицях для JOIN
    if re.search(r"JOIN", sql_query, re.IGNORECASE):
        tips.append("Перевірте, чи є індекси на полях, що використовуються в JOIN.")

    # 3. Перевірка на відсутність індексів на полях в WHERE
    if re.search(r"WHERE", sql_query, re.IGNORECASE):
        tips.append("Перевірте, чи є індекси на полях, що використовуються в WHERE.")

    # 4. Перевірка на використання ORDER BY без індексів
    if re.search(r"ORDER BY", sql_query, re.IGNORECASE):
        tips.append("Перевірте, чи є індекси на стовпцях, що використовуються в 'ORDER BY'.")

    # 5. Використання OR у WHERE
    if re.search(r"WHERE.*OR", sql_query, re.IGNORECASE):
        tips.append("Використання 'OR' у WHERE може бути повільним. Розгляньте можливість використання 'IN' або 'UNION'.")

    # 6. Використання LIKE з патерном %value%
    if re.search(r"LIKE '%.*%'", sql_query, re.IGNORECASE):
        tips.append("Використання 'LIKE' з патерном '%value%' може призвести до повільних запитів. Використовуйте індекси або повний текстовий пошук.")

    # 7. Перевірка на відсутність LIMIT для великих запитів
    if re.search(r"SELECT", sql_query, re.IGNORECASE) and "LIMIT" not in sql_query.upper():
        tips.append("Запит може повертати велику кількість рядків, розгляньте можливість використання LIMIT або пагінації.")

    # 8. Підзапити замінюйте на JOIN де можливо
    if re.search(r"SELECT.*FROM.*\(.*SELECT", sql_query, re.IGNORECASE):
        tips.append("Підзапити можуть бути повільними. Розгляньте можливість заміни підзапитів на JOIN.")

    # 9. Використання агрегатних функцій на великих наборах даних
    if re.search(r"(COUNT|SUM|AVG|MIN|MAX)\(", sql_query, re.IGNORECASE):
        tips.append("Агрегатні функції можуть бути повільними на великих наборах даних. Розгляньте можливість використання індексів.")

    # 10. Використання GROUP BY без індексів
    if re.search(r"GROUP BY", sql_query, re.IGNORECASE):
        tips.append("Перевірте, чи є індекси на стовпцях, що використовуються в 'GROUP BY'.")

    # Якщо не знайдено проблем, пропонуємо загальну рекомендацію
    if len(tips) == 0:
        tips.append("Не знайдено порад щодо оптимізації.")

    return jsonify({"tips": tips})


def create_query_history_db():
    conn = get_db_connection(DATABASE_USERS)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS query_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sql_query TEXT NOT NULL,
            result TEXT NOT NULL,
            execution_time REAL NULL,  -- Дозволено NULL
            time_status TEXT NULL,     -- Дозволено NULL
            query_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

create_query_history_db()

@app.route('/check_sql', methods=['POST'])
def check_sql():
    sql_query = request.form['sql_query']
    user_id = session.get('user_id')  # Отримуємо user_id із сесії, якщо є

    start_time = time.time()
    execution_time = 0
    result_data = None
    result_status = "Неуспішно"  # За замовчуванням
    error_message = None

    try:
        conn = get_db_connection(DATABASE_SQL)
        conn.row_factory = sqlite3.Row  # Встановлюємо фабрику для рядків
        cursor = conn.cursor()

        cursor.execute(sql_query)
        conn.commit()

        # Обробка SELECT-запитів
        if sql_query.strip().lower().startswith("select"):
            columns = [description[0] for description in cursor.description]  # Назви колонок
            rows = cursor.fetchall()

            # Перетворюємо об'єкти Row у списки
            row_data = [list(row) for row in rows]

            # Форматування даних для відповіді
            result_data = {
                "columns": columns,
                "rows": row_data
            }

        execution_time = time.time() - start_time
        execution_time = round(time.time() - start_time, 4) if 'start_time' in locals() else 0.0
        time_status = "Час виконання задовільний" if execution_time <= 1 else "Час виконання надто великий"

        result_status = "Успішно"  # Якщо виконання успішне
        error_message = None

    except sqlite3.Error as e:
        execution_time = time.time() - start_time
        time_status = "Не застосовується"
        error_message = str(e)

    finally:
        # Записуємо результат у таблицю `query_history`
        try:
            conn_users = get_db_connection(DATABASE_USERS)
            conn_users.execute('''
                INSERT INTO query_history (user_id, sql_query, result, execution_time, time_status, query_date)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, sql_query, result_status if not error_message else f"Помилка: {error_message}",
                  round(execution_time, 4) if execution_time else 0,
                  time_status))
            conn_users.commit()
        except sqlite3.Error as db_error:
            print(f"Помилка бази даних: {db_error}")
        finally:
            conn_users.close()

        if result_status == "Успішно":
            return jsonify({
                "valid": True,
                "message": "Запит виконано успішно",
                "result_data": result_data,  # Додаємо результат
                "execution_time": round(execution_time, 4),
                "time_status": time_status
            })
        else:
            return jsonify({
                "valid": False,
                "message": f"Помилка: {error_message}",
                "execution_time": round(execution_time, 4) if execution_time else 0,
                "time_status": time_status
            })





@app.route('/query_history')
def query_history():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection(DATABASE_USERS)
    history = conn.execute('''
        SELECT sql_query, result, execution_time, time_status, query_date
        FROM query_history WHERE user_id = ? ORDER BY query_date DESC
    ''', (user_id,)).fetchall()
    conn.close()

    return render_template('query_history.html', history=history)

# Завантаження файлів
@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({"success": False, "message": "Файл не надано"})

        file_content = file.read().decode('utf-8')
        table_data = json.loads(file_content)

        if not isinstance(table_data, list):
            return jsonify({"success": False, "message": "Неправильний формат файлу"})

        return jsonify({"success": True, "message": "Файл завантажено успішно!", "tables": table_data})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


import re
import sqlite3
from flask import request, jsonify

@app.route('/initialize_tables', methods=['POST'])
def initialize_tables():
    data = request.json  # Отримуємо дані з клієнта
    tables = data['tables']  # Масив таблиць
    import pprint
    print("Отримані дані з клієнта:")
    pprint.pprint(data)

    try:
        # Підключення до бази даних
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()

        # Включення підтримки зовнішніх ключів
        cursor.execute('PRAGMA foreign_keys = ON;')

        # Регулярний вираз для перевірки формату зовнішнього ключа
        foreign_key_pattern = re.compile(r'^[a-zA-Z0-9_]+\([a-zA-Z0-9_]+\)$')

        # Обробка кожної таблиці
        for table in tables:
            table_name = table['name']
            columns = table['columns']

            column_definitions = []
            foreign_key_clause = []  # Для зберігання всіх зовнішніх ключів

            for column in columns:
                column_name = column['name']
                column_type = column['type']
                is_primary_key = 'PRIMARY KEY' if column['primaryKey'] else ''
                is_not_null = 'NOT NULL' if column['notNull'] else ''
                is_unique = 'UNIQUE' if column.get('uniqueKey', False) else ''
                foreign_key = column['foreignKey']

                # Формуємо дефініцію стовпця
                column_definition = f"{column_name} {column_type} {is_primary_key} {is_not_null} {is_unique}".strip()
                column_definitions.append(column_definition)

                # Перевірка наявності зовнішнього ключа
                if foreign_key:
                    foreign_key = foreign_key.strip()

                    if not foreign_key_pattern.match(foreign_key):
                        return jsonify({'success': False, 'message': f'Невірний формат зовнішнього ключа для стовпця {column_name}'})

                    # Перевірка наявності таблиці та стовпця у базі даних
                    ref_table, ref_column = foreign_key.split('(')
                    ref_table_name = ref_table.strip()  # Видаляємо зайві пробіли
                    ref_column_name = ref_column.replace(')', '').strip()  # Видаляємо зайві пробіли і дужку

                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (ref_table_name,))
                    ref_table_exists = cursor.fetchone()
                    if not ref_table_exists:
                        return jsonify({'success': False, 'message': f'Таблиця {ref_table_name} не існує'})

                    cursor.execute(f"PRAGMA table_info({ref_table_name})")
                    columns_in_ref_table = cursor.fetchall()
                    ref_column_exists = any(col[1] == ref_column_name for col in columns_in_ref_table)
                    if not ref_column_exists:
                        return jsonify({'success': False, 'message': f'Стовпець {ref_column_name} в таблиці {ref_table_name} не існує'})

                    # Додаємо зовнішній ключ до списку
                    foreign_key_clause.append(f'FOREIGN KEY ({column_name}) REFERENCES {ref_table_name} ({ref_column_name})')
            unique_columns = [column['name'] for column in columns if column.get('unique', False)]

            # Формуємо SQL запит для створення таблиці
            create_table_sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(column_definitions)}"

            # Якщо є зовнішні ключі, додаємо їх
            if foreign_key_clause:
                create_table_sql += f", {', '.join(foreign_key_clause)}"

            # Додаємо унікальні ключі
            if unique_columns:
                unique_constraints = ", ".join([f"UNIQUE({col})" for col in unique_columns])
                create_table_sql += f", {unique_constraints}"

            create_table_sql += ")"  # Закриваємо запит
            print(f"SQL Запит для створення таблиці: {create_table_sql}")  # Виведення запиту для діагностики

            # Виконання SQL запиту для створення таблиці
            cursor.execute(create_table_sql)

        connection.commit()  # Збереження змін у базі даних
        return jsonify({'success': True, 'message': 'Таблиці успішно створено!'})

    except Exception as e:
        connection.rollback()  # Якщо сталася помилка, скасовуємо зміни
        return jsonify({'success': False, 'message': f'Помилка: {str(e)}'})

    finally:
        connection.close()

    import pprint
    print("Отримані дані з клієнта:")
    pprint.pprint(data)

@app.route('/get_table_structure/<table_name>', methods=['GET'])
def get_table_structure(table_name):
    conn = sqlite3.connect('database.db')  # Замість database.db використайте свою базу
    cursor = conn.cursor()

    try:
        # Отримання інформації про стовпці
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()

        # Формування даних для відображення
        structure = [
            {
                "column_id": col[0],
                "column_name": col[1],
                "data_type": col[2],
                "not_null": bool(col[3]),
                "default_value": col[4],
                "primary_key": bool(col[5])
            }
            for col in columns
        ]
        return jsonify(structure)
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/instructions')
def instructions():
    return render_template('instructions.html')

@app.route('/check_password', methods=['GET'])
def check_password():
    password = request.args.get('password')

    # Перевірка пароля на складність: мінімум 8 символів, одна велика літерка, одна цифра
    if len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'\d', password):
        return jsonify({"valid": True})  # Пароль відповідає вимогам
    else:
        return jsonify({"valid": False})  # Пароль не відповідає вимогам


import sqlite3

def get_db_structure_with_foreign_keys(db_name):
    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # Вмикаємо підтримку зовнішніх ключів
        cursor.execute("PRAGMA foreign_keys = ON;")

        # Отримуємо всі таблиці з бази даних
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';")
        tables = cursor.fetchall()

        db_structure = {}

        for table in tables:
            table_name = table[0]

            # Отримуємо стовпці таблиці та їх типи
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()

            column_info = []
            for col in columns:
                column_info.append({
                    'name': col[1],
                    'type': col[2],
                    'pk': bool(col[5]),  # Первинний ключ
                    'not_null': bool(col[3]),  # NOT NULL
                    'uniqueKey': False
                })

            # Перевірка індексів для унікальних ключів
            cursor.execute(f"PRAGMA index_list({table_name});")
            indexes = cursor.fetchall()

            for index in indexes:
                index_name = index[1]
                cursor.execute(f"PRAGMA index_info({index_name});")
                index_columns = cursor.fetchall()

                # Позначаємо стовпці, які мають унікальний індекс
                if index[2] == 1:  # Унікальний індекс
                    for index_column in index_columns:
                        column_name = index_column[2]  # Назва стовпця
                        for col in column_info:
                            if col['name'] == column_name:
                                col['uniqueKey'] = True

            # Обробка зовнішніх ключів
            cursor.execute(f"PRAGMA foreign_key_list({table_name});")
            fkeys = cursor.fetchall()

            foreign_keys = []
            for fk in fkeys:
                from_column = fk[3]  # Колонка з поточної таблиці
                to_table = fk[2]  # Таблиця, до якої веде зовнішній ключ
                to_column = fk[4]  # Колонка в цільовій таблиці

                # Додаємо інформацію про зовнішній ключ
                foreign_keys.append({
                    'from_column': from_column,
                    'to_table': to_table,
                    'to_column': to_column
                })

            # Зберігаємо структуру таблиці та зовнішні ключі
            db_structure[table_name] = {'columns': column_info, 'foreign_keys': foreign_keys}

        conn.close()
        return db_structure

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return None

@app.route('/visualize_db')
def visualize_db():
    db_name = 'database.db'  # Замініть на вашу базу даних
    db_structure = get_db_structure_with_foreign_keys(db_name)

    # Логуємо результат для перевірки
    import pprint
    pprint.pprint(db_structure)

    return render_template('visualization.html', db_structure=db_structure)

@app.route('/upload_table_data', methods=['POST'])
def upload_table_data():
    data = request.json  # Отримання даних у JSON
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    try:
        for table_name, rows in data.items():
            if not rows:
                continue

            # Генеруємо запит для вставки
            columns = rows[0].keys()
            placeholders = ", ".join(["?" for _ in columns])
            query = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"

            for row in rows:
                cursor.execute(query, tuple(row.values()))

        conn.commit()
        return jsonify({"success": True, "message": "Дані успішно завантажені у таблиці!"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        conn.close()

@app.route('/account_settings')
def account_settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    # Підключення до бази даних
    conn = get_db_connection(DATABASE_USERS)
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

    if not user:
        flash('Користувача не знайдено.', 'error')
        return redirect(url_for('login'))

    user_id = user['id']

    # Підрахунок статистики
    stats = conn.execute('''
        SELECT 
            SUM(CASE WHEN result = 'Успішно' THEN 1 ELSE 0 END) AS successful_queries,
            SUM(CASE WHEN result != 'Успішно' THEN 1 ELSE 0 END) AS failed_queries
        FROM query_history
        WHERE user_id = ?
    ''', (user_id,)).fetchone()
    conn.close()

    # Перевірка наявності статистики
    if not stats or (stats['successful_queries'] == 0 and stats['failed_queries'] == 0):
        no_stats_message = "Немає доступної статистики для відображення."
    else:
        no_stats_message = None

    user_info = {'username': username}
    stats = stats or {'successful_queries': 0, 'failed_queries': 0}  # Значення за замовчуванням
    return render_template(
        'account_settings.html',
        user_info=user_info,
        stats=stats,
        form_errors={},
        no_stats_message=no_stats_message
    )

@app.route('/change_username', methods=['POST'])
def change_username():
    if 'username' not in session:
        return redirect(url_for('login'))

    form_errors = {}
    current_username = session['username']
    new_username = request.form['new_username']

    conn = get_db_connection(DATABASE_USERS)

    # Перевірка наявності нового логіна
    existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (new_username,)).fetchone()

    if existing_user:
        form_errors['username'] = 'Користувач з таким логіном вже існує.'
    else:
        # Оновлення логіна
        conn.execute('UPDATE users SET username = ? WHERE username = ?', (new_username, current_username))
        conn.commit()
        session['username'] = new_username  # Оновлення сесії
        flash('Логін успішно змінено.', 'success')

    # Підрахунок статистики для відображення
    user = conn.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()
    stats = conn.execute('''
        SELECT 
            SUM(CASE WHEN result = 'Успішно' THEN 1 ELSE 0 END) AS successful_queries,
            SUM(CASE WHEN result != 'Успішно' THEN 1 ELSE 0 END) AS failed_queries
        FROM query_history
        WHERE user_id = ?
    ''', (user['id'],)).fetchone()

    conn.close()

    # Значення за замовчуванням, якщо статистика відсутня
    stats = stats or {'successful_queries': 0, 'failed_queries': 0}

    # Якщо є помилки, рендеримо сторінку з помилками
    if form_errors:
        return render_template('account_settings.html', user_info={'username': current_username}, form_errors=form_errors, stats=stats)

    # Якщо помилок немає, редиректимо до сторінки
    return redirect(url_for('account_settings'))


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    form_errors = {}
    username = session['username']
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Перевірка поточного пароля
    conn = get_db_connection(DATABASE_USERS)
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password'], current_password):
        form_errors['password'] = 'Поточний пароль невірний.'

    # Перевірка, чи новий пароль відповідає вимогам складності
    if len(new_password) < 8 or not re.search(r'[A-Z]', new_password) or not re.search(r'[a-z]', new_password) or not re.search(r'[0-9]', new_password):
        form_errors['password'] = 'Новий пароль має бути не менше 8 символів, містити великі й малі літери та цифру.'

    # Перевірка на збіг нового пароля з підтвердженням
    if new_password != confirm_password:
        form_errors['password'] = 'Новий пароль і підтвердження не співпадають.'

    # Якщо є помилки, повертаємо їх разом із формою
    if form_errors:
        return render_template('account_settings.html', user_info={'username': username}, form_errors=form_errors)

    # Оновлення пароля в базі даних
    hashed_password = generate_password_hash(new_password)
    conn = get_db_connection(DATABASE_USERS)
    conn.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
    conn.commit()
    conn.close()

    flash('Пароль успішно змінено.', 'success')
    return redirect(url_for('account_settings'))

@app.route('/reset_app', methods=['POST'])
def reset_app():
    try:
        clear_database()  # Викликаємо функцію очищення бази даних
        return jsonify({"success": True, "message": "База даних успішно очищена!"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})



if __name__ == '__main__':
    clear_database()
    app.run(debug=True)

