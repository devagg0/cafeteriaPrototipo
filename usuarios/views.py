import json
import hashlib
import jwt
import random
import re
import uuid 
from django.utils import timezone
from datetime import timedelta
from datetime import datetime, timedelta
from django.conf import settings
from django.core.mail import send_mail
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from functools import wraps
from .models import Rol, Usuario, Empleado, Cliente, Bitacora

JWT_ALGORITHM = getattr(settings, 'JWT_ALGORITHM', 'HS256')
JWT_EXPIRATION_MINUTES = int(getattr(settings, 'JWT_EXPIRATION_MINUTES', 60))


def hashear_contrasena(contrasena):
    """Hashea una contraseña con SHA-256"""
    return hashlib.sha256(contrasena.encode()).hexdigest()


def generar_token(usuario):
    payload = {
        'user_id': usuario.id_usuario,
        'rol': usuario.cod_rol.cod_rol,
        'exp': datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        'iat': datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def decodificar_token(token):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {'error': 'Token expirado'}
    except jwt.InvalidTokenError:
        return {'error': 'Token inválido'}


def obtener_usuario_desde_token(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, JsonResponse({'error': 'Autorización requerida'}, status=401)

    token = auth_header.split(' ', 1)[1]
    payload = decodificar_token(token)
    if isinstance(payload, dict) and payload.get('error'):
        return None, JsonResponse(payload, status=401)

    try:
        usuario = Usuario.objects.get(id_usuario=payload.get('user_id'))
        return usuario, None
    except Usuario.DoesNotExist:
        return None, JsonResponse({'error': 'Usuario no encontrado'}, status=404)


def registrar_bitacora(usuario, accion, detalles=None):
    Bitacora.objects.create(usuario=usuario, accion=accion, detalles=detalles or '')


def requiere_token_y_rol(roles_permitidos=None):
    """
    Decorador para validar token JWT y roles.
    roles_permitidos: lista de roles o None para cualquier rol autenticado.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            usuario, error_response = obtener_usuario_desde_token(request)
            if error_response:
                return error_response

            if roles_permitidos and usuario.cod_rol.cod_rol not in ['admin', 'empleado', 'cliente']:
                return JsonResponse({'error': 'Acceso denegado: rol insuficiente'}, status=403)

            request.usuario_autenticado = usuario
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def validar_acceso_cliente(request, cliente_id):
    """Valida si el usuario puede acceder al perfil de cliente específico"""
    usuario = request.usuario_autenticado
    if usuario.cod_rol.cod_rol == 'admin':
        return True
    elif usuario.cod_rol.cod_rol == 'cliente':
        try:
            cliente = Cliente.objects.get(id_usuario=usuario)
            return str(cliente.cod_cliente) == str(cliente_id)
        except Cliente.DoesNotExist:
            return False
    elif usuario.cod_rol.cod_rol in ['mesero', 'cocinero']:
        return True  # Empleados pueden ver clientes
    return False


def validar_acceso_empleado(request, empleado_id):
    """Valida si el usuario puede acceder al perfil de empleado específico"""
    usuario = request.usuario_autenticado
    if usuario.cod_rol.cod_rol == 'admin':
        return True
    elif usuario.cod_rol.cod_rol in ['mesero', 'cocinero']:
        # Empleados pueden ver otros empleados, pero no modificar
        return request.method == 'GET'
    return False


# 🔐 Control de intentos de login (en memoria)
INTENTOS_LOGIN = {}

MAX_INTENTOS = 3
TIEMPO_BLOQUEO_MIN = 10

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            correo = data.get('correo')
            contrasena = data.get('contrasena')

            if not correo or not contrasena:
                return JsonResponse(
                    {'error': 'Campos requeridos: correo, contrasena'},
                    status=400
                )

            # 🔒 1. VERIFICAR SI ESTÁ BLOQUEADO (AQUÍ)
            registro = INTENTOS_LOGIN.get(correo)

            if registro:
                bloqueado_hasta = registro.get('bloqueado_hasta')

                if bloqueado_hasta and timezone.now() < bloqueado_hasta:
                    minutos_restantes = int((bloqueado_hasta - timezone.now()).total_seconds() / 60)
                    return JsonResponse({
                        'error': f'Demasiados intentos. Intenta nuevamente en {minutos_restantes} minutos.'
                    }, status=403)

            try:
                usuario = Usuario.objects.get(
                    correo=correo,
                    contrasena=hashear_contrasena(contrasena)
                )

                # ✅ LOGIN CORRECTO → RESETEAR INTENTOS (AQUÍ)
                if correo in INTENTOS_LOGIN:
                    del INTENTOS_LOGIN[correo]

                token = generar_token(usuario)
                registrar_bitacora(usuario, 'login')

                return JsonResponse({
                    'mensaje': 'Login exitoso',
                    'token': token,
                    'usuario': {
                        'id': usuario.id_usuario,
                        'nombre': usuario.nombre,
                        'correo': usuario.correo,
                        'rol': usuario.cod_rol.cod_rol,
                        'rol_nombre': usuario.cod_rol.nombre,
                    }
                })

            except Usuario.DoesNotExist:

                # ❌ LOGIN FALLIDO → SUMAR INTENTOS (AQUÍ)
                registro = INTENTOS_LOGIN.get(correo, {'intentos': 0})
                registro['intentos'] += 1

                # 🔥 SI LLEGA AL MÁXIMO → BLOQUEAR
                if registro['intentos'] >= MAX_INTENTOS:
                    registro['bloqueado_hasta'] = timezone.now() + timedelta(minutes=TIEMPO_BLOQUEO_MIN)
                    INTENTOS_LOGIN[correo] = registro

                    return JsonResponse({
                        'error': 'Cuenta bloqueada por demasiados intentos. Intenta en 10 minutos.'
                    }, status=403)

                # 🔁 GUARDAR INTENTOS
                INTENTOS_LOGIN[correo] = registro

                restantes = MAX_INTENTOS - registro['intentos']

                return JsonResponse({
                    'error': f'Credenciales inválidas. Te quedan {restantes} intentos.'
                }, status=400)

        except json.JSONDecodeError:
            return JsonResponse(
                {'error': 'JSON inválido'},
                status=400
            )
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse(
        {'error': 'Método no permitido'},
        status=405
    )
    
@csrf_exempt
def recuperar_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            correo = data.get('correo')

            if not correo:
                return JsonResponse({'error': 'Correo requerido'}, status=400)

            try:
                usuario = Usuario.objects.get(correo=correo)

                # 🔐 generar código
                codigo = ''.join(random.choices('0123456789', k=6))
                usuario.codigo_recuperacion = codigo
                usuario.save()

                # 📩 enviar correo
                if settings.EMAIL_HOST_USER and settings.EMAIL_HOST_PASSWORD:
                    send_mail(
                        'Recuperación de contraseña',
                        f'Tu código de recuperación es: {codigo}',
                        f'NO REPLY <{settings.EMAIL_HOST_USER}>',
                        [usuario.correo],
                        fail_silently=True,
                    )

            except Usuario.DoesNotExist:
                # 🔒 no hacer nada (seguridad)
                pass

            # 🔥 respuesta SIEMPRE igual
            return JsonResponse({
                'mensaje': 'Revisa tu bandeja de entrada, se te envio el codigo'
            })

        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def verificar_codigo(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            correo = data.get('correo')
            codigo = data.get('codigo')

            if not correo or not codigo:
                return JsonResponse({'error': 'Datos incompletos'}, status=400)

            try:
                usuario = Usuario.objects.get(correo=correo)
            except Usuario.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

            if usuario.codigo_recuperacion != codigo:
                return JsonResponse({'error': 'Código incorrecto'}, status=400)

            return JsonResponse({'mensaje': 'Código válido'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def nueva_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            correo = data.get('correo')
            password = data.get('password')

            if not correo or not password:
                return JsonResponse({'error': 'Datos incompletos'}, status=400)

            try:
                usuario = Usuario.objects.get(correo=correo)
            except Usuario.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$', password):
                return JsonResponse({'error': 'Debe tener mayúscula, minúscula y número'}, status=400)

            usuario.contrasena = hashear_contrasena(password)
            usuario.codigo_recuperacion = None
            usuario.save()

            return JsonResponse({'mensaje': 'Contraseña actualizada'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def cambiar_password(request):
    if request.method == 'POST':
        usuario, error_response = obtener_usuario_desde_token(request)
        if error_response:
            return error_response

        try:
            data = json.loads(request.body)
            current_password = data.get('current_password')
            new_password = data.get('new_password')

            if not current_password or not new_password:
                return JsonResponse({'error': 'Datos incompletos'}, status=400)

            if usuario.contrasena != hashear_contrasena(current_password):
                return JsonResponse({'error': 'Contraseña actual incorrecta'}, status=400)

            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$', new_password):
                return JsonResponse({'error': 'Debe tener mayúscula, minúscula y número'}, status=400)

            usuario.contrasena = hashear_contrasena(new_password)
            usuario.save()
            registrar_bitacora(usuario, 'cambio de contraseña')
            return JsonResponse({'mensaje': 'Contraseña cambiada'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def lista_bitacora(request):
    usuario_autenticado, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response

    if request.method == 'GET':
        if usuario_autenticado.cod_rol.cod_rol != 'admin':
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        registros = Bitacora.objects.select_related('usuario').order_by('-timestamp')

        data = [{
            'usuario': b.usuario.nombre,
            'accion': b.accion,
            'detalle': b.detalles,
            'fecha': b.timestamp.strftime('%d/%m/%Y %H:%M:%S')
        } for b in registros]

        return JsonResponse(data, safe=False)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
        usuario, error_response = obtener_usuario_desde_token(request)
        if error_response:
            return error_response

        registrar_bitacora(usuario, 'logout')
        return JsonResponse({'mensaje': 'Cierre de sesión exitoso'})
    return JsonResponse({'error': 'Método no permitido'}, status=405)


def usuario_a_dict(usuario):
    empleado = getattr(usuario, 'empleado', None)
    cliente = getattr(usuario, 'cliente', None)
    return {
        'id_usuario': usuario.id_usuario,
        'nombre': usuario.nombre,
        'correo': usuario.correo,
        'cod_rol': usuario.cod_rol.cod_rol,
        'rol_nombre': usuario.cod_rol.nombre,
        'empleado': {
            'cod_empleado': empleado.cod_empleado,
            'cargo': empleado.cargo,
            'turno': empleado.turno,
        } if empleado else None,
        'cliente': {
            'cod_cliente': cliente.cod_cliente,
            'telefono': cliente.telefono,
            'direccion': cliente.direccion,
        } if cliente else None,
    }


@csrf_exempt
def lista_usuarios(request):

    if request.method == 'GET':
        usuario, error_response = obtener_usuario_desde_token(request)
        if error_response:
            return error_response

        if usuario.cod_rol.cod_rol != 'admin':
            return JsonResponse({'error': 'Acceso denegado: solo admin'}, status=403)

        usuarios = Usuario.objects.all()
        data = [usuario_a_dict(u) for u in usuarios]
        registrar_bitacora(usuario, 'consulta usuarios')

        return JsonResponse(data, safe=False)


    elif request.method == 'POST':
        try:
            data = json.loads(request.body)

            nombre = data.get('nombre')
            correo = data.get('correo')
            contrasena = data.get('contrasena')
            cod_rol = data.get('cod_rol', 'cliente')  # por defecto cliente

            # Validación básica
            if not nombre or not correo or not contrasena:
                return JsonResponse({
                    'error': 'Campos requeridos: nombre, correo, contrasena'
                }, status=400)

            # Validar correo único
            if Usuario.objects.filter(correo=correo).exists():
                return JsonResponse({'error': 'Correo ya registrado'}, status=400)

            # Obtener rol
            try:
                rol = Rol.objects.get(cod_rol=cod_rol)
            except Rol.DoesNotExist:
                return JsonResponse({'error': 'Rol no válido'}, status=400)

            # Crear usuario
            usuario_nuevo = Usuario.objects.create(
                nombre=nombre,
                correo=correo,
                contrasena=hashear_contrasena(contrasena),
                cod_rol=rol
            )
            
             # 🔥 CREAR CLIENTE AUTOMÁTICO
            if rol.cod_rol == 'cliente':
             from .models import Cliente
             
             telefono = str(usuario_nuevo.id_usuario).zfill(8)

             Cliente.objects.create(
        cod_cliente=f"C{usuario_nuevo.id_usuario}",
        id_usuario=usuario_nuevo,
        telefono=telefono,
        direccion='Sin dirección'
    )
             
             
            return JsonResponse({
                'mensaje': 'Usuario creado',
                'id_usuario': usuario_nuevo.id_usuario
            }, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        
        
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def detalle_usuario(request, user_id):
    usuario_autenticado, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response
    if usuario_autenticado.cod_rol.cod_rol != 'admin':
        return JsonResponse({'error': 'Acceso denegado: solo admin'}, status=403)

    try:
        usuario = Usuario.objects.get(id_usuario=user_id)
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

    if request.method == 'GET':
        registrar_bitacora(usuario_autenticado, 'consulta usuario', f'ID: {user_id}')
        return JsonResponse({
    'usuario': usuario_a_dict(usuario)
})

    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            usuario.nombre = data.get('nombre', usuario.nombre)
            usuario.correo = data.get('correo', usuario.correo)
            if 'contrasena' in data:
                usuario.contrasena = hashear_contrasena(data.get('contrasena'))
            usuario.save()
            registrar_bitacora(usuario_autenticado, 'actualiza usuario', f'ID: {user_id}')
            return JsonResponse({'mensaje': 'Usuario actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    elif request.method == 'DELETE':
        registrar_bitacora(usuario_autenticado, 'elimina usuario', f'ID: {user_id}')
        usuario.delete()
        return JsonResponse({'mensaje': 'Usuario eliminado'})

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def asignar_rol(request, user_id):
    usuario_autenticado, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response
    if usuario_autenticado.cod_rol.cod_rol != 'admin':
        return JsonResponse({'error': 'Acceso denegado: solo admin'}, status=403)

    try:
        usuario = Usuario.objects.get(id_usuario=user_id)
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            cod_rol = data.get('cod_rol')
            if not cod_rol:
                return JsonResponse({'error': 'Campo requerido: cod_rol'}, status=400)
            try:
                rol = Rol.objects.get(cod_rol=cod_rol)
            except Rol.DoesNotExist:
                return JsonResponse({'error': 'Rol no encontrado'}, status=400)
            usuario.cod_rol = rol
            usuario.save()
            registrar_bitacora(usuario_autenticado, 'asigna rol', f'Usuario ID: {user_id}, Rol: {cod_rol}')
            return JsonResponse({'mensaje': 'Rol asignado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


def lista_roles(request):
    usuario, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response
    if usuario.cod_rol.cod_rol != 'admin':
        return JsonResponse({'error': 'Acceso denegado: solo admin'}, status=403)

    if request.method == 'GET':
        roles = Rol.objects.all()
        data = [{'cod_rol': r.cod_rol, 'nombre': r.nombre, 'descripcion': r.descripcion} for r in roles]
        registrar_bitacora(usuario, 'consulta roles')
        return JsonResponse(data, safe=False)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def lista_empleados(request):
    usuario_autenticado, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response

    if request.method == 'GET':
        if usuario_autenticado.cod_rol.cod_rol not in ['admin', 'mesero', 'cocinero', 'emp']:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        empleados = Empleado.objects.all()
        data = [{
            'cod_empleado': e.cod_empleado,
            'usuario': usuario_a_dict(e.id_usuario),
            'cargo': e.cargo,
            'turno': e.turno,
        } for e in empleados]

        registrar_bitacora(usuario_autenticado, 'consulta empleados')
        return JsonResponse(data, safe=False)

    elif request.method == 'POST':
        if usuario_autenticado.cod_rol.cod_rol != 'admin':
            return JsonResponse({'error': 'Acceso denegado: solo admin'}, status=403)

        try:
            data = json.loads(request.body)

            nombre = data.get('nombre')
            correo = data.get('correo')
            contrasena = data.get('contrasena')
            cargo = data.get('cargo')

            if not all([nombre, correo, contrasena, cargo]):
                return JsonResponse({'error': 'Faltan datos'}, status=400)

            # 🔥 evitar duplicados
            if Usuario.objects.filter(correo=correo).exists():
                return JsonResponse({'error': 'El correo ya existe'}, status=400)

            # 🔥 rol empleado
            rol = Rol.objects.get(cod_rol='emp')

            # 🔥 crear usuario
            usuario = Usuario.objects.create(
                nombre=nombre,
                correo=correo,
                contrasena=hashear_contrasena(contrasena),
                cod_rol=rol
            )

            # 🔥 crear empleado
            import uuid
            empleado = Empleado.objects.create(
                cod_empleado=str(uuid.uuid4())[:6],
                id_usuario=usuario,
                cargo=cargo,
                turno='mañana'
            )

            registrar_bitacora(
                usuario_autenticado,
                'crea empleado',
                f'Empleado: {empleado.cod_empleado}'
            )

            return JsonResponse({
                'mensaje': 'Empleado creado',
                'cod_empleado': empleado.cod_empleado
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def detalle_empleado(request, employee_id):
    usuario_autenticado, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response

    if not validar_acceso_empleado(request, employee_id):
        return JsonResponse({'error': 'Acceso denegado'}, status=403)

    try:
        empleado = Empleado.objects.get(cod_empleado=employee_id)
    except Empleado.DoesNotExist:
        return JsonResponse({'error': 'Empleado no encontrado'}, status=404)

    if request.method == 'GET':
        data = {
            'cod_empleado': empleado.cod_empleado,
            'usuario': usuario_a_dict(empleado.id_usuario),
            'cargo': empleado.cargo,
            'turno': empleado.turno,
        }
        registrar_bitacora(usuario_autenticado, 'consulta empleado', f'ID: {employee_id}')
        return JsonResponse(data)

    elif request.method == 'PUT':
        if usuario_autenticado.cod_rol.cod_rol != 'admin':
            return JsonResponse({'error': 'Acceso denegado: solo admin puede modificar'}, status=403)

        try:
            data = json.loads(request.body)
            empleado.cargo = data.get('cargo', empleado.cargo)
            empleado.turno = data.get('turno', empleado.turno)
            empleado.save()
            registrar_bitacora(usuario_autenticado, 'actualiza empleado', f'ID: {employee_id}')
            return JsonResponse({'mensaje': 'Empleado actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

    elif request.method == 'DELETE':
        if usuario_autenticado.cod_rol.cod_rol != 'admin':
            return JsonResponse({'error': 'Acceso denegado: solo admin puede eliminar'}, status=403)

        registrar_bitacora(usuario_autenticado, 'elimina empleado', f'ID: {employee_id}')
        empleado.delete()
        return JsonResponse({'mensaje': 'Empleado eliminado'})

    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def lista_clientes(request):
    usuario_autenticado, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response

    if request.method == 'GET':
        if usuario_autenticado.cod_rol.cod_rol not in ['admin', 'mesero', 'cocinero', 'emp', 'cliente']:
            return JsonResponse({'error': 'Acceso denegado'}, status=403)

        # Si es cliente, solo ve su propio perfil
        if usuario_autenticado.cod_rol.cod_rol == 'cliente':
            try:
                cliente = Cliente.objects.get(id_usuario=usuario_autenticado)
                data = [{
                    'cod_cliente': cliente.cod_cliente,
                    'usuario': usuario_a_dict(cliente.id_usuario),
                    'telefono': cliente.telefono,
                    'direccion': cliente.direccion,
                }]
            except Cliente.DoesNotExist:
                data = []
        else:
            # Admin y empleados ven todos
            clientes = Cliente.objects.select_related('id_usuario').all()
            data = [{
                'cod_cliente': c.cod_cliente,
                'usuario': usuario_a_dict(c.id_usuario),
                'telefono': c.telefono,
                'direccion': c.direccion,
            } for c in clientes]

        registrar_bitacora(usuario_autenticado, 'consulta clientes')
        return JsonResponse(data, safe=False)

    elif request.method == 'POST':
        if usuario_autenticado.cod_rol.cod_rol != 'admin':
            return JsonResponse({'error': 'Acceso denegado: solo admin puede crear clientes'}, status=403)

        try:
            data = json.loads(request.body)
            cod_cliente = data.get('cod_cliente')
            user_id = data.get('id_usuario')
            direccion = data.get('direccion')

            if not all([cod_cliente, user_id, direccion]):
                return JsonResponse({'error': 'Campos requeridos: cod_cliente, id_usuario, direccion'}, status=400)

            try:
                usuario = Usuario.objects.get(id_usuario=user_id)
            except Usuario.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=400)

            if hasattr(usuario, 'cliente'):
                return JsonResponse({'error': 'Usuario ya es cliente'}, status=400)

            # 🔥 TELEFONO AUTOMÁTICO ÚNICO (SOLUCIÓN DEFINITIVA)
            telefono = str(usuario.id_usuario).zfill(8)

            cliente = Cliente.objects.create(
                cod_cliente=cod_cliente,
                id_usuario=usuario,
                telefono=telefono,
                direccion=direccion
            )

            registrar_bitacora(usuario_autenticado, 'crea cliente', f'Cliente: {cliente.cod_cliente}')

            return JsonResponse({
                'mensaje': 'Cliente creado',
                'cod_cliente': cliente.cod_cliente
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Método no permitido'}, status=405)

@csrf_exempt
def detalle_cliente(request, customer_id):
    usuario_autenticado, error_response = obtener_usuario_desde_token(request)
    if error_response:
        return error_response

    if not validar_acceso_cliente(request, customer_id):
        return JsonResponse({'error': 'Acceso denegado'}, status=403)

    try:
        cliente = Cliente.objects.get(cod_cliente=customer_id)
    except Cliente.DoesNotExist:
        return JsonResponse({'error': 'Cliente no encontrado'}, status=404)

    if request.method == 'GET':
        data = {
            'cod_cliente': cliente.cod_cliente,
            'usuario': usuario_a_dict(cliente.id_usuario),
            'telefono': cliente.telefono,
            'direccion': cliente.direccion,
        }
        registrar_bitacora(usuario_autenticado, 'consulta cliente', f'ID: {customer_id}')
        return JsonResponse(data)

    elif request.method == 'PUT':
        # Solo admin puede modificar, o el cliente su propio perfil
        puede_modificar = (
            usuario_autenticado.cod_rol.cod_rol == 'admin' or
            (usuario_autenticado.cod_rol.cod_rol == 'cliente' and cliente.id_usuario == usuario_autenticado)
        )
        if not puede_modificar:
            return JsonResponse({'error': 'Acceso denegado: no puede modificar este perfil'}, status=403)

        try:
            data = json.loads(request.body)
            cliente.telefono = data.get('telefono', cliente.telefono)
            cliente.direccion = data.get('direccion', cliente.direccion)
            cliente.save()
            registrar_bitacora(usuario_autenticado, 'actualiza cliente', f'ID: {customer_id}')
            return JsonResponse({'mensaje': 'Cliente actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

    elif request.method == 'DELETE':
        if usuario_autenticado.cod_rol.cod_rol != 'admin':
            return JsonResponse({'error': 'Acceso denegado: solo admin puede eliminar'}, status=403)

        registrar_bitacora(usuario_autenticado, 'elimina cliente', f'ID: {customer_id}')
        cliente.delete()
        return JsonResponse({'mensaje': 'Cliente eliminado'})

    return JsonResponse({'error': 'Método no permitido'}, status=405)

@csrf_exempt
def registro_cliente(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            nombre = data.get('nombre')
            correo = data.get('correo')
            contrasena = data.get('contrasena')

            if not all([nombre, correo, contrasena]):
                return JsonResponse({'error': 'Datos incompletos'}, status=400)

            if Usuario.objects.filter(correo=correo).exists():
                return JsonResponse({'error': 'Correo ya registrado'}, status=400)

            # 🔥 rol fijo cliente
            rol_cliente = Rol.objects.get(cod_rol='cliente')

            # 🔥 crear usuario
            usuario = Usuario.objects.create(
                nombre=nombre,
                correo=correo,
                contrasena=hashear_contrasena(contrasena),
                cod_rol=rol_cliente
            )

            # 🔥 crear cliente (SIN romper registro si falla)
            try:
                 telefono = str(usuario.id_usuario).zfill(8)

                 Cliente.objects.create(
                   cod_cliente=f"C{usuario.id_usuario}",
                   id_usuario=usuario,
                      telefono=telefono,
                      direccion='Sin dirección'
                       )
            except Exception as e:
                 print("Error creando cliente:", e)

            return JsonResponse({
                'mensaje': 'Usuario registrado correctamente',
                'id_usuario': usuario.id_usuario
            }, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Método no permitido'}, status=405)    
