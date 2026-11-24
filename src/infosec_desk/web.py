"""Flask: веб-приложение учёта обслуживания средств защиты информации."""
import csv
import json
import tempfile
import io
import os
import secrets
import sqlite3
from pathlib import Path
from flask import Flask, abort, jsonify, redirect, render_template, request, Response, session, send_file, url_for
from werkzeug.exceptions import HTTPException
from . import service
from .exchange import import_assets, FORMAT
from .db import connect, initialize
from .security import check_csrf, new_csrf_token
PACKAGE_DIR = Path(__file__).resolve().parent
PUBLIC_PAGES = {
    'overview': (
        'О службе',
        'Служба защиты информации организует приём и обработку обращений по эксплуатации СЗИ. Личные данные и заявки доступны только после входа.',
    ),
    'services': (
        'Услуги',
        'Служба оказывает помощь в настройке доступа, защите сети, антивирусной защите, криптографической защите и резервном копировании.',
    ),
    'submit': (
        'Как подать заявку',
        'Авторизуйтесь, откройте Новая заявка, укажите тему, описание, категорию и приоритет. После отправки заявке присваивается номер.',
    ),
    'categories': (
        'Категории',
        'Категория выбирается по типу проблемы: доступ, антивирус, сеть, криптография, резервное копирование или другое.',
    ),
    'priorities': (
        'Приоритеты',
        'Низкий приоритет выбирают для несрочных вопросов, обычный для типовых задач, высокий для значимых сбоев, критический для серьёзного нарушения защиты.',
    ),
    'status': (
        'Статусы заявок',
        'Новая - зарегистрирована. В работе - назначен специалист. Приостановлена - ожидается уточнение. Решена - проблема устранена. Закрыта - работа завершена.',
    ),
    'tracking': (
        'Отслеживание заявки',
        'Статус, специалист, комментарии и история доступны в личной карточке после входа. Поиск по номеру осуществляется в реестре.',
    ),
    'faq': (
        'Частые вопросы',
        'При изменении проблемы добавьте комментарий в карточку. Для уточнения исполнения откройте историю. Для смены доступа обратитесь к администратору.',
    ),
    'security': (
        'Конфиденциальность',
        'Сведения о заявках и пользователях не публикуются. Система проверяет роль и право доступа к каждому обращению.',
    ),
    'help': (
        'Помощь',
        'Для входа понадобится выданная учётная запись. Если пароль утрачен, обратитесь к администратору. Не отправляйте пароли через форму обратной связи.',
    ),
    'contacts': (
        'Контакты',
        'Написать службе можно через форму обратной связи. Сведения для обращения в организацию уточняются администратором.',
    ),
    'rules': (
        'Правила обращения',
        'Указывайте только данные, необходимые для диагностики. Не размещайте пароли, закрытые ключи и секреты в описаниях и вложениях.',
    ),
}


PUBLIC_DETAILS = {
    'overview': [
        'Служба принимает обращения о работе антивирусов, межсетевых экранов, средств шифрования и доступе к защищённым ресурсам.',
        'Каждому обращению присваивается номер. Ход работы фиксируется в карточке, поэтому при передаче задачи другому специалисту сохраняется её история.',
        'Обращения, исполнители и внутренний журнал не публикуются: для просмотра требуется вход под своей учётной записью.',
    ],
    'services': [
        'Доступ к ресурсу: проверка учётной записи, групп доступа, ошибок входа и сертификатов.',
        'Антивирусная и сетевая защита: проверка обновлений, событий защиты, подключения и сетевых ограничений.',
        'Криптография и резервные копии: диагностика сертификатов, средств шифрования и процедур восстановления.',
    ],
    'submit': [
        'Войдите в систему и выберите «Новая заявка». Укажите короткую тему, например «Не открывается защищённый ресурс».',
        'В описании напишите, когда возникла проблема, какой результат ожидался, что произошло и какие действия уже предпринимались.',
        'Выберите категорию, приоритет и при необходимости средство защиты. После отправки откройте карточку и запишите номер обращения.',
    ],
    'categories': [
        '«Управление доступом» выбирают, если не получается войти, открыть папку или работать с правами пользователя.',
        '«Антивирусная защита», «Сетевая защита» и «Криптографическая защита» подходят для неисправностей соответствующих средств.',
        '«Резервное копирование» относится к созданию и восстановлению копий. «Прочее» используйте, если подходящего варианта нет.',
    ],
    'priorities': [
        '«Низкий»: вопрос не блокирует работу. «Обычный»: требуется плановое устранение неполадки.',
        '«Высокий»: проблема мешает важной рабочей операции. «Критический»: нарушена защита или доступность значимой системы.',
        'Приоритет помогает организовать очередь, но не заменяет описание последствий. Не завышайте его без причины.',
    ],
    'status': [
        '«Новая»: обращение сохранено, исполнение ещё не началось. «В работе»: специалист приступил к задаче.',
        '«Приостановлена»: требуется дополнительная информация или внешнее действие. «Решена»: предложено или выполнено устранение.',
        '«Закрыта»: работа завершена. Предыдущие изменения остаются в истории карточки.',
    ],
    'tracking': [
        'После входа откройте «Заявки» и найдите своё обращение по номеру или теме.',
        'В карточке отображаются актуальный статус, ответственный специалист, комментарии, даты и последовательность изменений.',
        'Если требуется уточнение, добавьте комментарий в существующую заявку, чтобы сохранить переписку в одном месте.',
    ],
    'faq': [
        'Не получается войти? Проверьте логин и обратитесь к администратору, если нужна смена пароля. Не отправляйте пароль в сообщениях.',
        'Не видите заявку другого сотрудника? Заявитель получает доступ только к собственным обращениям; это штатное ограничение.',
        'Нужно добавить информацию? Откройте карточку обращения и используйте комментарий или разрешённое вложение.',
    ],
    'security': [
        'Не указывайте в обращениях пароли, закрытые ключи, токены и другие секреты.',
        'Доступ к карточкам заявок предоставляется по роли. Администратор может управлять пользователями, специалист обрабатывает заявки, заявитель видит собственные.',
        'Файлы прикрепляются только в разрешённых форматах и доступны пользователям, которым доступна сама заявка.',
    ],
    'help': [
        'Первое действие: проверьте, можете ли вы войти в личный кабинет под выданным логином.',
        'При создании заявки используйте понятную тему и опишите проблему без специальных сокращений, если их смысл неоднозначен.',
        'По вопросам работы сайта можно написать через форму обратной связи. В учебном экземпляре настоящий адрес технической поддержки не задан.',
    ],
    'contacts': [
        'Для вопроса по работе сайта используйте форму «Обратная связь». Сообщение появится в административном разделе.',
        'Действующий номер телефона и адрес службы устанавливаются организацией. В учебном экземпляре они намеренно не выдуманы.',
        'По вопросам конкретной заявки используйте комментарии в её карточке после авторизации.',
    ],
    'rules': [
        'Одна заявка должна описывать одну проблему. Это позволяет назначить ответственного и завершить работу с понятным результатом.',
        'Указывайте наблюдаемые признаки: сообщение об ошибке, дату появления и затронутый ресурс без раскрытия конфиденциальных сведений.',
        'Сохраняйте переписку в карточке обращения. Для новой независимой проблемы создавайте отдельную заявку.',
    ],
}


def create_app(
    db_path: str | Path | None = None,
    secret_key: str | None = None,
) -> Flask:
    db_path = Path(db_path or os.getenv('INFOSEC_DB_PATH', 'instance/infosec.sqlite3')).resolve()
    initialize(db_path)
    app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/static')
    app.config.update(
        SECRET_KEY=secret_key or os.getenv('INFOSEC_SECRET_KEY') or secrets.token_urlsafe(48),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.getenv('INFOSEC_SECURE_COOKIES', '0') == '1',
        MAX_CONTENT_LENGTH=2_100_000,
    )
    app.db_path = db_path
    app.jinja_env.filters['ticket_no'] = lambda value: f'З-{value:06d}'
    app.jinja_env.globals.update(categories=service.CATEGORIES, priorities=service.PRIORITIES, statuses=service.STATUSES, roles=service.ROLES, public_pages=PUBLIC_PAGES)

    def current_user():
        uid = session.get('user_id')
        return service.find_user(db_path, uid) if uid is not None else None

    def show(template, title, **data):
        if 'csrf_token' not in session:
            session['csrf_token'] = new_csrf_token()
        message = session.pop('message', '')
        error = session.pop('error', '')
        return render_template(template, user=current_user(), csrf_token=session['csrf_token'], title=title, message=message, error=error, settings=service.get_settings(db_path), **data)

    def forward(path, message='', error=''):
        if message:
            session['message'] = message
        if error:
            session['error'] = error
        return redirect(path, code=303)

    def require_user(roles=None):
        user = current_user()
        if user is None:
            abort(401)
        if roles and user['role'] not in roles:
            abort(403)
        return user

    def secure_form():
        if not check_csrf(session.get('csrf_token'), request.form.get('csrf_token')):
            abort(403)
        return request.form

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        restricted_prefixes = ('/tickets', '/users', '/audit', '/admin', '/my-',
                               '/notifications', '/profile', '/attachments', '/export')
        if request.path.startswith(restricted_prefixes):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/favicon.ico')
    def favicon():
        return redirect('/static/favicon.svg')

    @app.get('/health')
    def health():
        with connect(db_path) as db:
            db.execute('SELECT 1').fetchone()
        return jsonify(status='ok')

    @app.get('/public')
    def public_home():
        return redirect('/public/overview', code=303)

    @app.get('/public/<slug>')
    def public_page(slug):
        if slug not in PUBLIC_PAGES:
            abort(404)
        heading, body = PUBLIC_PAGES[slug]
        return show('public_page.html', heading, heading=heading, body=body, slug=slug, items=service.list_services(db_path, active_only=True) if slug == 'services' else [], details=PUBLIC_DETAILS[slug])

    @app.get('/feedback')
    def feedback_page():
        return show('feedback.html', 'Обратная связь')

    @app.post('/feedback')
    def feedback_post():
        data = secure_form()
        try:
            service.create_feedback(db_path, str(data.get('sender_name', '')), str(data.get('sender_email', '')), str(data.get('subject', '')), str(data.get('body', '')))
        except ValueError as exc:
            return forward('/feedback', error=str(exc))
        return forward('/feedback', message='Сообщение зарегистрировано')

    @app.get('/login')
    def login_page():
        if current_user():
            return redirect('/', code=303)
        return show('login.html', 'Вход')

    @app.post('/login')
    def login_post():
        data = secure_form()
        user = service.authenticate(db_path, str(data.get('username', '')), str(data.get('password', '')))
        if user is None:
            return forward('/login', error='Неверный логин или пароль')
        session.clear()
        session['user_id'] = user['id']
        session['csrf_token'] = new_csrf_token()
        return redirect('/', code=303)

    @app.post('/logout')
    def logout():
        secure_form()
        session.clear()
        return redirect('/login', code=303)

    @app.get('/')
    def dashboard():
        user = require_user()
        return show('dashboard.html', 'Панель управления', stats=service.statistics(db_path, user), tickets=service.list_tickets(db_path, user, limit=8))

    @app.get('/tickets')
    def tickets_page():
        user = require_user()
        status = request.args.get('status', '')
        q = request.args.get('q', '')
        return show('tickets.html', 'Заявки', tickets=service.list_tickets(db_path, user, status, q, limit=500), status_filter=status, search=q)

    @app.get('/tickets/new')
    def new_ticket_page():
        require_user()
        return show('ticket_new.html', 'Новая заявка', assets=service.assets(db_path), services=service.list_services(db_path, True))

    @app.post('/tickets')
    def create_ticket_post():
        user = require_user()
        data = secure_form()
        try:
            asset_id = int(data['asset_id']) if data.get('asset_id') else None
            ticket_id = service.create_ticket(db_path, user, str(data.get('title', '')), str(data.get('description', '')), str(data.get('category', '')), str(data.get('priority', '')), asset_id)
        except (ValueError, sqlite3.IntegrityError) as exc:
            return forward('/tickets/new', error=str(exc))
        return forward(f'/tickets/{ticket_id}', message='Заявка зарегистрирована')

    @app.get('/tickets/<int:ticket_id>')
    def ticket_page(ticket_id):
        user = require_user()
        details = service.get_ticket(db_path, user, ticket_id)
        if details is None:
            abort(404)
        ticket, comments, events = details
        assignees = [x for x in service.users(db_path) if x['active'] and x['role'] != 'requester']
        return show('ticket_detail.html', f'Заявка З-{ticket_id:06d}', ticket=ticket, comments=comments, events=events, assignees=assignees, transitions=service.TRANSITIONS[ticket['status']], attachments=service.list_attachments(db_path, ticket_id), history=service.status_history(db_path, ticket_id))

    @app.post('/tickets/<int:ticket_id>/comments')
    def comment_post(ticket_id):
        user = require_user()
        data = secure_form()
        try:
            service.add_comment(db_path, user, ticket_id, str(data.get('body', '')))
        except ValueError as exc:
            return forward(f'/tickets/{ticket_id}', error=str(exc))
        except PermissionError:
            abort(404)
        return forward(f'/tickets/{ticket_id}', message='Комментарий сохранён')

    @app.post('/tickets/<int:ticket_id>/update')
    def update_ticket_post(ticket_id):
        user = require_user({'operator', 'admin'})
        data = secure_form()
        try:
            assignee_id = int(data['assignee_id']) if data.get('assignee_id') else None
            service.update_ticket(db_path, user, ticket_id, str(data.get('status', '')), assignee_id)
        except (ValueError, sqlite3.IntegrityError) as exc:
            return forward(f'/tickets/{ticket_id}', error=str(exc))
        return forward(f'/tickets/{ticket_id}', message='Изменения сохранены')

    @app.post('/tickets/<int:ticket_id>/attachments')
    def attachment_post(ticket_id):
        user = require_user()
        secure_form()
        upload = request.files.get('attachment')
        if not upload:
            return forward(f'/tickets/{ticket_id}', error='Выберите файл')
        try:
            service.add_attachment(db_path, user, ticket_id, upload.filename, upload.mimetype, upload.read(2000001))
        except PermissionError:
            abort(404)
        except ValueError as exc:
            return forward(f'/tickets/{ticket_id}', error=str(exc))
        return forward(f'/tickets/{ticket_id}', message='Файл прикреплён')

    @app.get('/attachments/<int:attachment_id>')
    def attachment_download(attachment_id):
        user = require_user()
        item = service.get_attachment(db_path, user, attachment_id)
        if item is None:
            abort(404)
        return send_file(io.BytesIO(item['content']), mimetype=item['mime_type'], as_attachment=True, download_name=item['filename'])

    @app.get('/assets')
    def assets_page():
        require_user()
        return show('assets.html', 'Средства защиты', assets=service.assets(db_path))

    @app.post('/assets')
    def assets_post():
        require_user({'admin'})
        d = secure_form()
        try:
            service.add_asset(db_path, *[str(d.get(x, '')) for x in ('inventory_no', 'name', 'location', 'protection_class', 'description')])
        except (ValueError, sqlite3.IntegrityError) as exc:
            return forward('/assets', error=str(exc))
        return forward('/assets', message='Средство защиты добавлено')

    @app.post('/assets/<int:asset_id>/edit')
    def asset_edit_post(asset_id):
        user = require_user({'admin'})
        d = secure_form()
        try:
            service.edit_asset(db_path, user, asset_id, *[str(d.get(x, '')) for x in ('inventory_no', 'name', 'location', 'protection_class', 'description')])
        except (ValueError, sqlite3.IntegrityError) as exc:
            return forward('/assets', error=str(exc))
        return forward('/assets', message='Данные СЗИ обновлены')

    @app.post('/assets/<int:asset_id>/delete')
    def asset_delete_post(asset_id):
        user = require_user({'admin'})
        secure_form()
        try:
            service.delete_asset(db_path, user, asset_id)
        except ValueError as exc:
            return forward('/assets', error=str(exc))
        return forward('/assets', message='СЗИ исключено из справочника')

    @app.get('/users')
    def users_page():
        require_user({'admin'})
        return show('users.html', 'Пользователи', users=service.users(db_path))

    @app.post('/users')
    def users_post():
        require_user({'admin'})
        d = secure_form()
        try:
            service.create_user(db_path, *[str(d.get(x, '')) for x in ('username', 'full_name', 'password', 'role')])
        except (ValueError, sqlite3.IntegrityError) as exc:
            return forward('/users', error=str(exc))
        return forward('/users', message='Пользователь создан')

    @app.post('/users/<int:user_id>/edit')
    def user_edit_post(user_id):
        user = require_user({'admin'})
        d = secure_form()
        try:
            service.edit_user(db_path, user, user_id, str(d.get('username', '')), str(d.get('full_name', '')), str(d.get('role', 'requester')), d.get('active') == '1')
        except (ValueError, sqlite3.IntegrityError) as exc:
            return forward('/users', error=str(exc))
        return forward('/users', message='Данные пользователя изменены')

    @app.post('/users/<int:user_id>/delete')
    def user_delete_post(user_id):
        user = require_user({'admin'})
        secure_form()
        try:
            service.delete_user(db_path, user, user_id)
        except ValueError as exc:
            return forward('/users', error=str(exc))
        return forward('/users', message='Пользователь отключён')

    @app.get('/audit')
    def audit_page():
        require_user({'admin'})
        return show('audit.html', 'Журнал действий', events=service.audit_events(db_path))

    @app.get('/admin/services')
    def admin_services():
        require_user({'admin'})
        return show('admin_services.html', 'Каталог услуг', items=service.list_services(db_path))

    @app.post('/admin/services')
    def admin_services_post():
        require_user({'admin'})
        d = secure_form()
        try:
            service.add_service(db_path, *[str(d.get(x, '')) for x in ('code', 'name', 'description', 'category')])
        except (ValueError, sqlite3.IntegrityError) as exc:
            return forward('/admin/services', error=str(exc))
        return forward('/admin/services', message='Услуга добавлена')

    @app.post('/admin/services/<int:service_id>/toggle')
    def admin_service_toggle(service_id):
        require_user({'admin'})
        secure_form()
        service.toggle_service(db_path, service_id)
        return forward('/admin/services', message='Статус услуги изменён')

    @app.get('/admin/feedback')
    def admin_feedback():
        require_user({'admin'})
        return show('admin_feedback.html', 'Обращения посетителей', items=service.list_feedback(db_path))

    @app.post('/admin/feedback/<int:feedback_id>/processed')
    def feedback_processed(feedback_id):
        require_user({'admin'})
        secure_form()
        service.mark_feedback(db_path, feedback_id)
        return forward('/admin/feedback', message='Обращение обработано')

    @app.get('/admin/settings')
    def admin_settings():
        require_user({'admin'})
        return show('admin_settings.html', 'Настройки службы')

    @app.post('/admin/settings')
    def admin_settings_post():
        require_user({'admin'})
        d = secure_form()
        try:
            for key in ('site_title', 'help_email', 'office_hours'):
                service.set_setting(db_path, key, str(d.get(key, '')))
        except ValueError as exc:
            return forward('/admin/settings', error=str(exc))
        return forward('/admin/settings', message='Настройки сохранены')

    @app.get('/admin/data-exchange')
    def data_exchange():
        require_user({'admin'})
        return show('admin_exchange.html', 'Обмен справочником СЗИ')

    @app.get('/admin/assets.json')
    def export_assets_json():
        require_user({'admin'})
        with connect(db_path) as db:
            records = [dict(item) for item in db.execute(
                "SELECT inventory_no, name, location, protection_class, description "
                "FROM assets ORDER BY inventory_no"
            )]
        result = json.dumps({'format': FORMAT, 'items': records},
                            ensure_ascii=False, indent=2)
        return Response(result, content_type='application/json; charset=utf-8',
                        headers={'Content-Disposition': 'attachment; filename="assets.json"',
                                 'Cache-Control': 'no-store'})

    @app.post('/admin/assets.json')
    def import_assets_json():
        require_user({'admin'})
        secure_form()
        upload = request.files.get('assets_file')
        if upload is None or not upload.filename.lower().endswith('.json'):
            return forward('/admin/data-exchange', error='Выберите файл JSON.')
        data = upload.read(2_100_000)
        if len(data) > 2_097_152:
            return forward('/admin/data-exchange', error='Размер файла превышает 2 МБ.')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'assets.json'
            path.write_bytes(data)
            try:
                result = import_assets(db_path, path)
            except ValueError as error:
                return forward('/admin/data-exchange', error=str(error))
        message = f"Добавлено: {result['added']}; пропущено: {result['skipped']}."
        return forward('/admin/data-exchange', message=message)

    @app.get('/admin/analytics')
    def admin_analytics():
        require_user({'admin'})
        return show('admin_analytics.html', 'Статистика службы', stats=service.admin_analytics(db_path))

    @app.get('/profile')
    def profile():
        user = require_user()
        return show('profile.html', 'Личный кабинет', profile=user)

    @app.get('/my-activity')
    def my_activity():
        user = require_user()
        return show('my_activity.html', 'Моя активность', items=service.list_tickets(db_path, user, limit=100))

    @app.get('/notifications')
    def notifications():
        user = require_user()
        return show('notifications.html', 'Уведомления', items=service.user_notifications(db_path, user['id']))

    @app.post('/notifications/read')
    def notifications_read():
        user = require_user()
        secure_form()
        service.mark_notifications_read(db_path, user['id'])
        return forward('/notifications', message='Уведомления прочитаны')

    @app.get('/my-help')
    def personal_help():
        require_user()
        return show('personal_help.html', 'Помощь в личном кабинете')

    def records_for_export():
        user = require_user({'operator', 'admin'})
        return service.list_tickets(db_path, user, request.args.get('status', ''), request.args.get('q', ''))

    def export_rows(records):
        yield ['Номер', 'Тема', 'Категория', 'Приоритет', 'Статус', 'Автор', 'Исполнитель', 'Создана', 'Решена', 'Закрыта']
        for row in records:
            yield [f"З-{row['id']:06d}", row['title'], service.CATEGORIES[row['category']], service.PRIORITIES[row['priority']], service.STATUSES[row['status']], row['author_name'], row['assignee_name'] or '', row['created_at'], row['resolved_at'] or '', row['closed_at'] or '']

    def spreadsheet_safe(value):
        v = str(value)
        return "'" + v if v.lstrip().startswith(('=', '+', '-', '@')) else v

    @app.get('/export.csv')
    def export_csv():
        records = records_for_export()
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=';')
        for row in export_rows(records):
            writer.writerow([spreadsheet_safe(v) for v in row])
        return Response('\ufeff' + buf.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename="infosec_tickets.csv"', 'Cache-Control': 'no-store'})

    @app.get('/export.xlsx')
    def export_xlsx():
        from openpyxl import Workbook
        from openpyxl.styles import Font
        wb = Workbook()
        ws = wb.active
        ws.title = 'Реестр заявок'
        for row in export_rows(records_for_export()):
            ws.append([spreadsheet_safe(v) for v in row])
        for cell in ws[1]:
            cell.font = Font(bold=True, color='000000')
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions
        for col, width in {'A': 14, 'B': 38, 'C': 25, 'D': 17, 'E': 19, 'F': 26, 'G': 26, 'H': 21, 'I': 21, 'J': 21}.items():
            ws.column_dimensions[col].width = width
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        return send_file(buf, download_name='infosec_tickets.xlsx', as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

    @app.errorhandler(HTTPException)
    def handle_http_error(exc):
        if exc.code == 401:
            return redirect('/login', code=303)
        explanations = {403: ('Недостаточно прав', 'Для просмотра раздела нужна другая роль или действительная проверка формы.'), 404: ('Страница не найдена', 'Проверьте адрес или вернитесь на главную страницу.')}
        title, explanation = explanations.get(exc.code, ('Ошибка запроса', 'Запрос не может быть выполнен.'))
        return (show('error.html', title, explanation=explanation, status_code=exc.code), exc.code)
    return app
