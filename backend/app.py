from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from cryptography.fernet import Fernet
from datetime import datetime, timedelta, timezone, date
import os
from dotenv import load_dotenv
import json
import random
import string
import qrcode
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
import pyotp
from werkzeug.urls import url_parse
from PIL import Image, ImageDraw

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))
CORS(app)
csrf = CSRFProtect(app)

# Настройка базы данных
database_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'drug_verification.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = False  # Для разработки
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице.'
login_manager.login_message_category = 'info'

# Key file path using os.path for cross-platform compatibility
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encryption_key.txt')

# Generate or load encryption key
def get_encryption_key():
    try:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, 'rb') as f:
                key = f.read()
                # Проверяем, что ключ корректный
                Fernet(key)
                return key
    except Exception:
        # Если ключ некорректный или файл поврежден, создаем новый
        pass
        
    # Генерируем новый ключ
    key = Fernet.generate_key()
    # Сохраняем ключ в файл
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

ENCRYPTION_KEY = get_encryption_key()
fernet = Fernet(ENCRYPTION_KEY)

# Список фармацевтических компаний
PHARMACEUTICAL_COMPANIES = [
    "Фармстандарт",
    "Биокад",
    "Р-Фарм",
    "Генериум",
    "Верофарм",
    "Акрихин",
    "Нижфарм",
    "Валента Фарм",
    "Петровакс",
    "Материа Медика"
]

# Список лекарственных форм
DRUG_FORMS = [
    "Таблетки",
    "Капсулы",
    "Раствор для инъекций",
    "Сироп",
    "Мазь",
    "Крем",
    "Капли",
    "Спрей"
]

# Список популярных лекарств
DRUG_NAMES = [
    "Нурофен",
    "Парацетамол",
    "Анальгин",
    "Ибупрофен",
    "Аспирин",
    "Амоксициллин",
    "Азитромицин",
    "Лоратадин",
    "Омепразол",
    "Пенталгин"
]

# Информация о лекарствах
DRUG_INFO = {
    "Нурофен": {
        "description": "Нурофен - нестероидный противовоспалительный препарат из группы производных пропионовой кислоты. Оказывает обезболивающее, жаропонижающее и противовоспалительное действие.",
        "usage": "Способ применения:\n- Взрослые и дети старше 12 лет: по 1-2 таблетки 3-4 раза в сутки\n- Интервал между приемами: не менее 4 часов\n- Максимальная суточная доза: 6 таблеток (1200 мг)\n- Принимать после еды, запивая водой\n- Длительность лечения без консультации врача: не более 5 дней",
        "side_effects": "Частые побочные эффекты:\n- Тошнота, рвота, диарея\n- Боль в животе, метеоризм\n- Головная боль, головокружение\n- Бессонница, повышенная утомляемость\n\nРедкие, но серьезные:\n- Аллергические реакции\n- Обострение астмы\n- Нарушения со стороны ЖКТ",
        "contraindications": "Абсолютные противопоказания:\n- Язвенная болезнь желудка и 12-перстной кишки\n- Индивидуальная непереносимость\n- Бронхиальная астма\n- Нарушения свертываемости крови\n- Беременность (3-й триместр)\n- Детский возраст до 12 лет",
        "storage": "Условия хранения:\n- Хранить при температуре не выше 25°C\n- В защищенном от света и влаги месте\n- В недоступном для детей месте\n- Срок годности: 2 года",
        "image_url": "/static/images/placeholder.png"
    },
    "Парацетамол": {
        "description": "Парацетамол - анальгетик и антипиретик, эффективно снижает температуру и уменьшает боль различного происхождения. Действующее вещество: ацетаминофен.",
        "usage": "Способ применения:\n- Взрослые и дети старше 12 лет: по 1-2 таблетки каждые 4-6 часов\n- Максимальная суточная доза: 8 таблеток (4000 мг)\n- Минимальный интервал между приемами: 4 часа\n- Можно принимать независимо от приема пищи\n- При высокой температуре: начать с 2 таблеток",
        "side_effects": "Возможные побочные эффекты:\n- Аллергические реакции\n- Тошнота и боль в животе\n- Повышение активности печеночных ферментов\n\nРедкие, но серьезные:\n- Нарушение функции печени при передозировке\n- Тромбоцитопения\n- Анемия",
        "contraindications": "Противопоказания:\n- Тяжелые нарушения функции печени\n- Острый гепатит\n- Индивидуальная непереносимость\n- Дефицит глюкозо-6-фосфатдегидрогеназы\n- С осторожностью при беременности и кормлении",
        "storage": "Условия хранения:\n- Хранить при комнатной температуре (15-25°C)\n- В сухом, защищенном от света месте\n- В оригинальной упаковке\n- Срок годности указан на упаковке",
        "image_url": "https://example.com/images/paracetamol.jpg"
    },
    "Анальгин": {
        "description": "Анальгин (Метамизол натрия) - анальгетик и антипиретик с выраженным обезболивающим и жаропонижающим действием. Эффективен при сильных болях и высокой температуре.",
        "usage": "Способ применения:\n- Взрослые: по 1 таблетке 2-3 раза в день\n- При сильной боли: 2 таблетки однократно\n- Максимальная суточная доза: 4 таблетки\n- Принимать после еды\n- Курс лечения без консультации врача: не более 3 дней",
        "side_effects": "Возможные побочные эффекты:\n- Аллергические реакции\n- Снижение артериального давления\n- Агранулоцитоз (редко)\n- Кожные реакции\n\nРедкие, но серьезные:\n- Анафилактический шок\n- Нарушения кроветворения\n- Бронхоспазм",
        "contraindications": "Противопоказания:\n- Нарушения кроветворения\n- Бронхиальная астма\n- Индивидуальная непереносимость\n- Беременность и кормление грудью\n- Дефицит глюкозо-6-фосфатдегидрогеназы\n- Детский возраст до 14 лет",
        "storage": "Условия хранения:\n- Хранить при температуре до 25°C\n- В защищенном от света месте\n- В недоступном для детей месте\n- Срок годности: 5 лет",
        "image_url": "https://example.com/images/analgin.jpg"
    },
    "Ибупрофен": {
        "description": "Ибупрофен - нестероидный противовоспалительный препарат. Оказывает обезболивающее, жаропонижающее и противовоспалительное действие. Эффективен при болях различного происхождения.",
        "usage": "Способ применения:\n- Взрослые: по 1-2 таблетки 3-4 раза в сутки\n- Максимальная разовая доза: 400 мг (2 таблетки)\n- Максимальная суточная доза: 1200 мг\n- Принимать после еды\n- Длительность приема без консультации врача: не более 5 дней",
        "side_effects": "Возможные побочные эффекты:\n- Боль в желудке\n- Тошнота, рвота\n- Головная боль\n- Аллергические реакции\n\nРедкие, но серьезные:\n- Желудочно-кишечные кровотечения\n- Нарушение функции почек\n- Повышение артериального давления",
        "contraindications": "Противопоказания:\n- Язвенная болезнь желудка\n- Тяжелые заболевания печени и почек\n- Нарушения свертываемости крови\n- Беременность (3-й триместр)\n- Аспириновая астма\n- Детский возраст до 12 лет",
        "storage": "Условия хранения:\n- Хранить при температуре не выше 25°C\n- В сухом, защищенном от света месте\n- В плотно закрытой упаковке\n- Срок годности: 3 года",
        "image_url": "https://example.com/images/ibuprofen.jpg"
    },
    "Аспирин": {
        "description": "Аспирин (Ацетилсалициловая кислота) - нестероидный противовоспалительный препарат. Оказывает обезболивающее, жаропонижающее, противовоспалительное и антиагрегантное действие.",
        "usage": "Способ применения:\n- Взрослые: по 1 таблетке 3 раза в день\n- При лихорадке: 1-2 таблетки\n- Максимальная суточная доза: 8 таблеток\n- Принимать после еды\n- Запивать полным стаканом воды",
        "side_effects": "Возможные побочные эффекты:\n- Боль в желудке\n- Тошнота\n- Скрытые кровотечения\n- Аллергические реакции\n\nРедкие, но серьезные:\n- Желудочно-кишечные кровотечения\n- Синдром Рея у детей\n- Бронхоспазм",
        "contraindications": "Противопоказания:\n- Язвенная болезнь желудка\n- Бронхиальная астма\n- Нарушения свертываемости крови\n- Беременность (3-й триместр)\n- Детский возраст до 15 лет\n- Дефицит глюкозо-6-фосфатдегидрогеназы",
        "storage": "Условия хранения:\n- Хранить при температуре не выше 25°C\n- В сухом месте\n- В защищенном от света месте\n- Срок годности: 3 года",
        "image_url": "https://example.com/images/aspirin.jpg"
    }
}

# Модель для ролей пользователей
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(200))
    users = db.relationship('User', backref='role', lazy=True)

# Модель для пользователей
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    company_name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Новые поля для 2FA
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    two_factor_confirmed = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, role_name):
        return self.role and self.role.name == role_name
        
    def get_2fa_uri(self):
        """Генерирует URI для QR-кода 2FA"""
        if not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
        return pyotp.totp.TOTP(self.two_factor_secret).provisioning_uri(
            name=self.email,
            issuer_name="Drug Verification System"
        )
        
    def verify_2fa(self, code):
        """Проверяет код 2FA"""
        if not self.two_factor_secret:
            return False
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(code)

    def get_id(self):
        return str(self.id)

# Добавляем связь между Drug и User
class Drug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)  # Добавляем название лекарства
    form = db.Column(db.String(100), nullable=False)  # Добавляем форму выпуска
    manufacturer = db.Column(db.String(100), nullable=False)
    expiration_date = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('drugs', lazy=True))

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('activity_logs', lazy=True))

def encrypt_data(data):
    """Encrypt data before generating QR code"""
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt data from QR code"""
    return fernet.decrypt(encrypted_data.encode()).decode()

def generate_qr_code(data):
    """Генерирует QR-код из данных и возвращает его в формате base64"""
    from PIL import Image, ImageDraw
    import os
    
    # Создаем QR-код с высоким уровнем коррекции ошибок
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # Высокий уровень коррекции для логотипа
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Создаем QR-код с белым фоном
    qr_image = qr.make_image(fill_color="black", back_color="white").convert('RGBA')
    
    try:
        # Создаем логотип
        logo_size = qr_image.size[0] // 4  # Размер логотипа - 1/4 от размера QR-кода
        logo = Image.new('RGBA', (logo_size, logo_size), 'white')
        draw = ImageDraw.Draw(logo)
        
        # Рисуем синий круг
        draw.ellipse([0, 0, logo_size-1, logo_size-1], fill='#2563eb')
        
        # Рисуем белый крест
        cross_size = logo_size // 2
        cross_pos = (logo_size - cross_size) // 2
        draw.rectangle([cross_pos, cross_size//4, cross_pos + cross_size//3, cross_pos + cross_size], fill='white')
        draw.rectangle([cross_size//4, cross_pos, cross_pos + cross_size, cross_pos + cross_size//3], fill='white')
        
        # Вычисляем позицию для размещения логотипа в центре
        pos = ((qr_image.size[0] - logo_size) // 2, (qr_image.size[1] - logo_size) // 2)
        
        # Накладываем логотип на QR-код
        qr_image.paste(logo, pos, logo)
    except Exception as e:
        app.logger.error(f"Error adding logo to QR code: {str(e)}")
        # Если не удалось добавить логотип, используем QR-код без него
    
    # Сохраняем изображение в байтовый буфер
    buffer = BytesIO()
    qr_image.save(buffer, format="PNG")
    
    # Конвертируем в base64
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/api/info')
def api_info():
    return jsonify({
        'message': 'Welcome to Drug Verification API',
        'endpoints': {
            'verify': '/verify - POST request to verify drug QR code'
        }
    })

@app.route('/verify/<encrypted_data>')
def verify_page(encrypted_data):
    """Страница для публичной проверки лекарства по QR-коду"""
    try:
        # Расшифровываем данные
        decrypted_data = decrypt_data(encrypted_data)
        qr_data = json.loads(decrypted_data)
        
        # Получаем серийный номер
        serial_number = qr_data.get('sn')
        if not serial_number:
            return render_template('verify.html', 
                error='Неверный формат QR-кода')
            
        # Проверяем существование лекарства
        drug = Drug.query.filter_by(serial_number=serial_number).first()
        if not drug:
            return render_template('verify.html', 
                error='Лекарство не найдено в базе данных')

        # Проверяем срок годности
        if drug.expiration_date < datetime.now():
            return render_template('verify.html', 
                error='Срок годности лекарства истек')

        # Если лекарство еще не использовано, отмечаем его как использованное
        first_scan = False
        if not drug.is_used:
            drug.is_used = True
            db.session.commit()
            first_scan = True
            app.logger.info(f"Лекарство {serial_number} отмечено как использованное при первом сканировании")
        
        # Получаем информацию о лекарстве
        drug_info = DRUG_INFO.get(drug.name, {
            "description": f"Лекарственный препарат {drug.name}, производимый компанией {drug.manufacturer}.",
            "usage": "Способ применения:\n- Внимательно прочитайте инструкцию перед применением\n- Следуйте рекомендациям врача",
            "side_effects": "Возможные побочные эффекты:\n- Индивидуальная непереносимость компонентов\n- Аллергические реакции",
            "contraindications": "Противопоказания:\n- Индивидуальная непереносимость",
            "storage": "Условия хранения:\n- Хранить при температуре не выше 25°C\n- В сухом, защищенном от света месте\n- В недоступном для детей месте"
        })

        # Подготавливаем данные для отображения
        drug_data = {
            'name': drug.name,
            'manufacturer': drug.manufacturer,
            'serial_number': serial_number,
            'form': drug.form,
            'expiration_date': drug.expiration_date.strftime('%d.%m.%Y'),
            'is_used': True,  # Всегда будет True, так как отмечаем при первом сканировании
            'info': drug_info,
            'first_scan': first_scan  # Добавляем флаг первого сканирования
        }
        
        return render_template('verify.html', drug=drug_data)
        
    except Exception as e:
        app.logger.error(f"Ошибка при проверке лекарства: {str(e)}")
        return render_template('verify.html', 
            error=f'Ошибка при проверке лекарства: {str(e)}')

@app.route('/create-test-drug', methods=['POST'])
def create_test_drug():
    try:
        # Проверяем, что пользователь авторизован
        if 'user_id' not in session:
            return jsonify({
                'error': 'Необходима авторизация'
            }), 401

        with db.session.begin_nested():
            year = datetime.utcnow().year
            random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
            serial_number = f"RU-{year}-{random_suffix}"
            
            drug_name = random.choice(DRUG_NAMES)
            manufacturer = random.choice(PHARMACEUTICAL_COMPANIES)
            drug_form = random.choice(DRUG_FORMS)
            
            test_drug = Drug(
                serial_number=serial_number,
                name=drug_name,
                form=drug_form,
                manufacturer=manufacturer,
                expiration_date=datetime.utcnow() + timedelta(days=365 * 2),
                user_id=session['user_id']
            )
            
            db.session.add(test_drug)
            
            # Подготавливаем минимальные данные для QR кода
            qr_data = {
                'sn': serial_number
            }
            
            # Преобразуем данные в строку JSON и шифруем
            encrypted_data = encrypt_data(json.dumps(qr_data))
            
            # Создаем URL для верификации
            verification_url = f"http://127.0.0.1:5000/verify/{encrypted_data}"
            
            # Генерируем QR-код с оптимизированными настройками
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(verification_url)
            qr.make(fit=True)
            
            # Создаем изображение QR-кода
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            qr_code = base64.b64encode(buffer.getvalue()).decode()
            
            # Фиксируем изменения в базе данных
            db.session.commit()
            
            # Возвращаем информацию для главной страницы
            return jsonify({
                'message': 'Лекарство успешно добавлено в базу',
                'drug': {
                    'serial_number': serial_number,
                    'manufacturer': manufacturer,
                    'name': drug_name,
                    'form': drug_form
                },
                'verification_url': verification_url,
                'qr_code': f"data:image/png;base64,{qr_code}"
            })
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка при создании лекарства: {str(e)}")
        return jsonify({
            'error': 'Произошла ошибка при создании лекарства',
            'details': str(e)
        }), 500

@app.route('/api/drugs', methods=['GET'])
@login_required
def list_drugs():
    try:
        drugs = Drug.query.filter_by(user_id=current_user.id).order_by(Drug.created_at.desc()).all()
        return jsonify({
            'drugs': [{
                'serial_number': drug.serial_number,
                'manufacturer': drug.manufacturer,
                'expiration_date': drug.expiration_date.isoformat(),
                'is_used': drug.is_used,
                'created_at': drug.created_at.isoformat(),
                'name': drug.name,
                'form': drug.form
            } for drug in drugs]
        })
    except Exception as e:
        app.logger.error(f"Error fetching drugs: {str(e)}")
        return jsonify({'error': 'Ошибка при загрузке данных'}), 500

@app.route('/api/drugs/<serial_number>', methods=['GET'])
def get_drug_details(serial_number):
    try:
        drug = Drug.query.filter_by(serial_number=serial_number).first()
        if not drug:
            return jsonify({'error': 'Лекарство не найдено'}), 404
            
        # Подготавливаем базовую информацию о лекарстве
        drug_data = {
            'serial_number': drug.serial_number,
            'manufacturer': drug.manufacturer,
            'expiration_date': drug.expiration_date.isoformat(),
            'is_used': drug.is_used,
            'created_at': drug.created_at.isoformat(),
            'name': drug.name,
            'form': drug.form
        }

        # Если лекарство не использовано, добавляем QR-код и ссылку для верификации
        if not drug.is_used:
            # Подготавливаем данные для QR кода
            qr_data = {
                'sn': drug.serial_number
            }
            
            # Шифруем данные
            encrypted_data = encrypt_data(json.dumps(qr_data))
            
            # Создаем URL для верификации
            verification_url = f"http://127.0.0.1:5000/verify/{encrypted_data}"
            
            # Генерируем QR-код
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(verification_url)
            qr.make(fit=True)
            
            # Создаем изображение QR-кода
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            qr_code = base64.b64encode(buffer.getvalue()).decode()
            
            # Добавляем QR-код и ссылку в ответ
            drug_data['verification_url'] = verification_url
            drug_data['qr_code'] = f"data:image/png;base64,{qr_code}"
            
        return jsonify({
            'drug': drug_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/drugs/<serial_number>/mark-used', methods=['POST'])
@csrf.exempt
def mark_drug_as_used(serial_number):
    """Отметить лекарство как использованное"""
    try:
        drug = Drug.query.filter_by(serial_number=serial_number).first()
        if not drug:
            return jsonify({'error': 'Лекарство не найдено'}), 404
            
        if drug.is_used:
            return jsonify({'error': 'Лекарство уже отмечено как использованное'}), 400
            
        drug.is_used = True
        db.session.commit()
        
        # Логируем действие
        app.logger.info(f"Лекарство {serial_number} отмечено как использованное")
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка при отметке лекарства как использованного: {str(e)}")
        return jsonify({'error': str(e)}), 500

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Пожалуйста, введите имя пользователя и пароль', 'error')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash('Ваш аккаунт деактивирован. Обратитесь к администратору.', 'error')
                return render_template('login.html')

            # Если у пользователя включена 2FA
            if user.two_factor_enabled and user.two_factor_confirmed:
                session['_2fa_user_id'] = user.id
                return redirect(url_for('verify_2fa'))

            # Если 2FA не включена, выполняем обычный вход
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Записываем в журнал
            log_activity(user.id, 'login', 'Успешный вход')

            return redirect(url_for('dashboard'))

        flash('Неверное имя пользователя или пароль', 'error')
        return render_template('login.html')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        company_name = request.form.get('company_name')

        if not all([username, email, password, confirm_password, company_name]):
            flash('Пожалуйста, заполните все поля', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'error')
            return render_template('register.html')

        try:
            # Создаем нового пользователя с ролью по умолчанию
            default_role = Role.query.filter_by(name='user').first()
            if not default_role:
                default_role = Role(name='user', description='Regular user')
                db.session.add(default_role)
                db.session.commit()
            
            user = User(
                username=username,
                email=email,
                company_name=company_name,
                role=default_role
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Автоматически авторизуем пользователя после регистрации
            session['user_id'] = user.id
            session['role_name'] = user.role.name if user.role else 'user'
            
            flash('Регистрация успешна! Добро пожаловать в систему!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Ошибка при регистрации: {str(e)}")
            flash('Произошла ошибка при регистрации. Пожалуйста, попробуйте позже.', 'error')
            return render_template('register.html')
        
    return render_template('register.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if current_user.is_authenticated:
        user_id = current_user.id
        log_activity(user_id, 'logout', 'Выход из системы')
        logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=current_user)

@login_manager.user_loader
def load_user(user_id):
    if user_id is None:
        return None
    try:
        return User.query.get(int(user_id))
    except (TypeError, ValueError):
        return None

def log_activity(user_id, action, details):
    """Log user activity"""
    try:
        log = ActivityLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Error logging activity: {str(e)}")
        db.session.rollback()

@app.route('/profile')
@login_required
def profile():
    activity_logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(50).all()
    return render_template('profile.html', user=current_user, activity_logs=activity_logs)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    email = request.form.get('email')
    company_name = request.form.get('company_name')
    new_password = request.form.get('new_password')

    if email:
        current_user.email = email
        log_activity(current_user.id, 'update_profile', f'Updated email to {email}')

    if company_name:
        current_user.company_name = company_name
        log_activity(current_user.id, 'update_profile', f'Updated company name to {company_name}')

    if new_password:
        current_user.set_password(new_password)
        log_activity(current_user.id, 'update_profile', 'Updated password')

    try:
        db.session.commit()
        flash('Профиль успешно обновлен', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при обновлении профиля', 'error')
        log_activity(current_user.id, 'error', f'Failed to update profile: {str(e)}')

    return redirect(url_for('profile'))

@app.route('/register-drug', methods=['GET', 'POST'])
@login_required
def register_drug():
    if request.method == 'POST':
        try:
            # Получаем данные из формы
            name = request.form.get('name', '').strip()
            form = request.form.get('form', '').strip()
            manufacturer = request.form.get('manufacturer', '').strip()
            expiration_date = request.form.get('expiration_date', '').strip()
            batch_number = request.form.get('batch_number', '').strip()
            
            try:
                quantity = int(request.form.get('quantity', '1'))
            except ValueError:
                quantity = 1

            app.logger.info(f"Received form data: name={name}, form={form}, manufacturer={manufacturer}, "
                          f"expiration_date={expiration_date}, batch_number={batch_number}, quantity={quantity}")

            # Проверяем обязательные поля
            if not all([name, form, manufacturer, expiration_date, batch_number]):
                missing_fields = []
                if not name: missing_fields.append("название лекарства")
                if not form: missing_fields.append("форма выпуска")
                if not manufacturer: missing_fields.append("производитель")
                if not expiration_date: missing_fields.append("срок годности")
                if not batch_number: missing_fields.append("номер партии")
                
                flash(f'Пожалуйста, заполните следующие поля: {", ".join(missing_fields)}', 'error')
                return render_template('register_drug.html', today=date.today().isoformat())

            # Проверяем количество
            if not 1 <= quantity <= 100:
                flash('Количество должно быть от 1 до 100', 'error')
                return render_template('register_drug.html', today=date.today().isoformat())

            # Проверяем срок годности
            try:
                exp_date = datetime.strptime(expiration_date, '%Y-%m-%d').date()
                if exp_date <= date.today():
                    flash('Срок годности должен быть больше текущей даты', 'error')
                    return render_template('register_drug.html', today=date.today().isoformat())
            except ValueError as e:
                app.logger.error(f"Date parsing error: {str(e)}")
                flash('Неверный формат даты', 'error')
                return render_template('register_drug.html', today=date.today().isoformat())

            # Генерируем QR-коды
            qr_codes = []
            year = str(date.today().year)
            
            # Начинаем транзакцию
            try:
                for i in range(quantity):
                    # Генерируем уникальный серийный номер
                    serial_number = f"RU-{year}-{batch_number}-{str(i+1).zfill(3)}"
                    
                    # Проверяем уникальность серийного номера
                    existing_drug = Drug.query.filter_by(serial_number=serial_number).first()
                    if existing_drug:
                        app.logger.warning(f"Serial number {serial_number} already exists")
                        flash(f'Серийный номер {serial_number} уже существует', 'error')
                        continue

                    # Создаем данные для QR-кода
                    qr_data = {
                        'sn': serial_number,
                        'name': name,
                        'manufacturer': manufacturer,
                        'form': form,
                        'exp_date': expiration_date
                    }
                    
                    try:
                        encrypted_data = encrypt_data(json.dumps(qr_data))
                        verification_url = url_for('verify_page', encrypted_data=encrypted_data, _external=True)
                        
                        # Генерируем QR-код
                        qr = qrcode.QRCode(
                            version=1,
                            error_correction=qrcode.constants.ERROR_CORRECT_L,
                            box_size=10,
                            border=4,
                        )
                        qr.add_data(verification_url)
                        qr.make(fit=True)
                        
                        # Создаем изображение QR-кода
                        qr_image = qr.make_image(fill_color="black", back_color="white")
                        buffered = BytesIO()
                        qr_image.save(buffered, format="PNG")
                        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
                        
                        # Создаем объект Drug
                        drug = Drug(
                            name=name,
                            form=form,
                            manufacturer=manufacturer,
                            expiration_date=exp_date,
                            serial_number=serial_number,
                            user_id=current_user.id,
                            created_at=datetime.now()
                        )
                        db.session.add(drug)
                        
                        qr_codes.append({
                            'code': f"data:image/png;base64,{qr_base64}",
                            'serial_number': serial_number,
                            'url': verification_url
                        })
                        
                    except Exception as e:
                        app.logger.error(f"Error generating QR code for {serial_number}: {str(e)}")
                        continue

                if not qr_codes:
                    db.session.rollback()
                    flash('Не удалось создать ни одного QR-кода. Возможно, все серийные номера уже существуют.', 'error')
                    return render_template('register_drug.html', today=date.today().isoformat())

                # Сохраняем все изменения в базе данных
                db.session.commit()
                
                # Логируем успешную регистрацию
                log_activity(current_user.id, 'register_drugs', 
                           f'Зарегистрировано {len(qr_codes)} упаковок препарата {name}, партия {batch_number}')
                
                return render_template('register_drug.html',
                                     success=f'Успешно зарегистрировано {len(qr_codes)} упаковок',
                                     qr_codes=qr_codes,
                                     today=date.today().isoformat())
                                     
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Database error: {str(e)}")
                flash('Ошибка при сохранении данных в базу', 'error')
                return render_template('register_drug.html', today=date.today().isoformat())
                                 
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during drug registration: {str(e)}")
            flash('Произошла ошибка при регистрации. Пожалуйста, попробуйте снова.', 'error')
            return render_template('register_drug.html', today=date.today().isoformat())

    # GET запрос - показываем форму
    return render_template('register_drug.html', today=date.today().isoformat())

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.two_factor_confirmed:
        flash('Двухфакторная аутентификация уже настроена', 'error')
        return redirect(url_for('profile'))
        
    if request.method == 'POST':
        code = request.form.get('code')
        if not code:
            flash('Введите код подтверждения', 'error')
            return redirect(url_for('setup_2fa'))
            
        if current_user.verify_2fa(code):
            current_user.two_factor_enabled = True
            current_user.two_factor_confirmed = True
            db.session.commit()
            flash('Двухфакторная аутентификация успешно настроена', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверный код подтверждения', 'error')
            return redirect(url_for('setup_2fa'))
    
    # Генерируем QR-код для настройки 2FA
    uri = current_user.get_2fa_uri()
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code = f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode()}"
    
    return render_template('setup_2fa.html', 
        qr_code=qr_code,
        secret=current_user.two_factor_secret)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Проверяем, что у пользователя есть незавершенная аутентификация
    user_id = session.get('_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        code = request.form.get('code')
        if not code:
            flash('Введите код подтверждения')
            return redirect(url_for('verify_2fa'))
            
        user = User.query.get(user_id)
        if not user:
            session.pop('_2fa_user_id', None)
            return redirect(url_for('login'))
            
        if user.verify_2fa(code):
            # Очищаем временные данные
            session.pop('_2fa_user_id', None)
            
            # Выполняем вход
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Записываем в журнал
            log_activity(user.id, 'login', 'Успешный вход с 2FA')
            
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный код подтверждения')
            return redirect(url_for('verify_2fa'))
            
    return render_template('verify_2fa.html')

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    current_user.two_factor_enabled = False
    current_user.two_factor_confirmed = False
    current_user.two_factor_secret = None
    db.session.commit()
    flash('Двухфакторная аутентификация отключена', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    with app.app_context():
        # Создаем все таблицы
        db.create_all()
        
        # Создаем роли, если их нет
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Administrator')
            db.session.add(admin_role)
            
        user_role = Role.query.filter_by(name='user').first()
        if not user_role:
            user_role = Role(name='user', description='Regular user')
            db.session.add(user_role)
            
        manufacturer_role = Role.query.filter_by(name='manufacturer').first()
        if not manufacturer_role:
            manufacturer_role = Role(name='manufacturer', description='Pharmaceutical manufacturer')
            db.session.add(manufacturer_role)
        
        db.session.commit()
        
        # Создаем тестового пользователя, если его нет
        test_user = User.query.filter_by(username='test').first()
        if not test_user:
            try:
                test_user = User(
                    username='test',
                    email='test@example.com',
                    company_name='Тестовая Компания',
                    role=manufacturer_role
                )
                test_user.set_password('test123')
                db.session.add(test_user)
                db.session.commit()
                print('Создан тестовый пользователь:')
                print('Логин: test')
                print('Пароль: test123')
            except Exception as e:
                print(f'Ошибка при создании тестового пользователя: {str(e)}')
                db.session.rollback()
            
    app.run(debug=True) 