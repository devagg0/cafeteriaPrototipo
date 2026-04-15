import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .models import Rol, PerfilUsuario, Empleado, Cliente


@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            correo = data.get('correo')
            contrasena = data.get('contrasena')
            user = authenticate(username=correo, password=contrasena)
            if user:
                login(request, user)
                return JsonResponse({'mensaje': 'Inicio de sesión exitoso', 'usuario_id': user.id})
            else:
                return JsonResponse({'error': 'Credenciales inválidas'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return JsonResponse({'mensaje': 'Cierre de sesión exitoso'})
    return JsonResponse({'error': 'Método no permitido'}, status=405)


def usuario_a_dict(user):
    perfil = getattr(user, 'perfil', None)
    empleado = getattr(user, 'empleado_perfil', None)
    cliente = getattr(user, 'cliente_perfil', None)
    return {
        'id_usuario': user.id,
        'nombre': user.first_name,
        'correo': user.email,
        'telefono': perfil.telefono if perfil else '',
        'direccion': perfil.direccion if perfil else '',
        'rol': {'cod_rol': perfil.rol.cod_rol, 'nombre': perfil.rol.nombre} if perfil else None,
        'empleado': {
            'cod_empleado': empleado.cod_empleado,
            'cargo': empleado.cargo,
            'turno': empleado.turno,
            'fecha_contratacion': empleado.fecha_contratacion.isoformat() if empleado.fecha_contratacion else None,
            'notas': empleado.notas
        } if empleado else None,
        'cliente': {
            'cod_cliente': cliente.cod_cliente,
            'correo_contacto': cliente.correo_contacto,
            'puntos_fidelidad': cliente.puntos_fidelidad,
            'notas': cliente.notas
        } if cliente else None,
    }


@csrf_exempt
def lista_usuarios(request):
    if request.method == 'GET':
        usuarios = User.objects.all()
        data = [usuario_a_dict(u) for u in usuarios]
        return JsonResponse(data, safe=False)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            nombre = data.get('nombre')
            correo = data.get('correo')
            contrasena = data.get('contrasena')
            cod_rol = data.get('cod_rol')
            telefono = data.get('telefono', '')
            direccion = data.get('direccion', '')
            if not all([nombre, correo, contrasena, cod_rol]):
                return JsonResponse({'error': 'Campos requeridos: nombre, correo, contrasena, cod_rol'}, status=400)
            if User.objects.filter(email=correo).exists():
                return JsonResponse({'error': 'Correo ya registrado'}, status=400)
            try:
                rol = Rol.objects.get(cod_rol=cod_rol)
            except Rol.DoesNotExist:
                return JsonResponse({'error': 'Rol no encontrado'}, status=400)
            user = User.objects.create_user(username=correo, email=correo, password=contrasena, first_name=nombre)
            PerfilUsuario.objects.create(usuario=user, rol=rol, telefono=telefono, direccion=direccion)
            return JsonResponse({'mensaje': 'Usuario creado', 'usuario_id': user.id}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def detalle_usuario(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
    if request.method == 'GET':
        return JsonResponse(usuario_a_dict(user))
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            user.first_name = data.get('nombre', user.first_name)
            user.email = data.get('correo', user.email)
            user.save()
            perfil = getattr(user, 'perfil', None)
            if perfil:
                perfil.telefono = data.get('telefono', perfil.telefono)
                perfil.direccion = data.get('direccion', perfil.direccion)
                perfil.save()
            return JsonResponse({'mensaje': 'Usuario actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    elif request.method == 'DELETE':
        user.delete()
        return JsonResponse({'mensaje': 'Usuario eliminado'})
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def asignar_rol(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        perfil = getattr(user, 'perfil', None)
        if not perfil:
            return JsonResponse({'error': 'Usuario sin perfil'}, status=400)
    except User.DoesNotExist:
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
            perfil.rol = rol
            perfil.save()
            return JsonResponse({'mensaje': 'Rol asignado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


def lista_roles(request):
    if request.method == 'GET':
        roles = Rol.objects.all()
        data = [{'cod_rol': r.cod_rol, 'nombre': r.nombre, 'descripcion': r.descripcion} for r in roles]
        return JsonResponse(data, safe=False)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def lista_empleados(request):
    if request.method == 'GET':
        empleados = Empleado.objects.all()
        data = [{
            'cod_empleado': e.cod_empleado,
            'usuario': usuario_a_dict(e.usuario),
            'cargo': e.cargo,
            'turno': e.turno,
            'fecha_contratacion': e.fecha_contratacion.isoformat() if e.fecha_contratacion else None,
            'notas': e.notas
        } for e in empleados]
        return JsonResponse(data, safe=False)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_id = data.get('user_id')
            cargo = data.get('cargo')
            turno = data.get('turno')
            fecha_contratacion = data.get('fecha_contratacion')
            notas = data.get('notas', '')
            if not all([user_id, cargo, turno]):
                return JsonResponse({'error': 'Campos requeridos: user_id, cargo, turno'}, status=400)
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=400)
            if hasattr(user, 'empleado_perfil'):
                return JsonResponse({'error': 'Usuario ya es empleado'}, status=400)
            empleado = Empleado.objects.create(
                usuario=user, cargo=cargo, turno=turno,
                fecha_contratacion=fecha_contratacion, notas=notas
            )
            return JsonResponse({'mensaje': 'Empleado creado', 'cod_empleado': empleado.cod_empleado}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def detalle_empleado(request, employee_id):
    try:
        empleado = Empleado.objects.get(cod_empleado=employee_id)
    except Empleado.DoesNotExist:
        return JsonResponse({'error': 'Empleado no encontrado'}, status=404)
    if request.method == 'GET':
        data = {
            'cod_empleado': empleado.cod_empleado,
            'usuario': usuario_a_dict(empleado.usuario),
            'cargo': empleado.cargo,
            'turno': empleado.turno,
            'fecha_contratacion': empleado.fecha_contratacion.isoformat() if empleado.fecha_contratacion else None,
            'notas': empleado.notas
        }
        return JsonResponse(data)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            empleado.cargo = data.get('cargo', empleado.cargo)
            empleado.turno = data.get('turno', empleado.turno)
            empleado.fecha_contratacion = data.get('fecha_contratacion', empleado.fecha_contratacion)
            empleado.notas = data.get('notas', empleado.notas)
            empleado.save()
            return JsonResponse({'mensaje': 'Empleado actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    elif request.method == 'DELETE':
        empleado.delete()
        return JsonResponse({'mensaje': 'Empleado eliminado'})
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def lista_clientes(request):
    if request.method == 'GET':
        clientes = Cliente.objects.all()
        data = [{
            'cod_cliente': c.cod_cliente,
            'usuario': usuario_a_dict(c.usuario),
            'correo_contacto': c.correo_contacto,
            'puntos_fidelidad': c.puntos_fidelidad,
            'notas': c.notas
        } for c in clientes]
        return JsonResponse(data, safe=False)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_id = data.get('user_id')
            correo_contacto = data.get('correo_contacto', '')
            puntos_fidelidad = data.get('puntos_fidelidad', 0)
            notas = data.get('notas', '')
            if not user_id:
                return JsonResponse({'error': 'Campo requerido: user_id'}, status=400)
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=400)
            if hasattr(user, 'cliente_perfil'):
                return JsonResponse({'error': 'Usuario ya es cliente'}, status=400)
            cliente = Cliente.objects.create(
                usuario=user, correo_contacto=correo_contacto,
                puntos_fidelidad=puntos_fidelidad, notas=notas
            )
            return JsonResponse({'mensaje': 'Cliente creado', 'cod_cliente': cliente.cod_cliente}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def detalle_cliente(request, customer_id):
    try:
        cliente = Cliente.objects.get(cod_cliente=customer_id)
    except Cliente.DoesNotExist:
        return JsonResponse({'error': 'Cliente no encontrado'}, status=404)
    if request.method == 'GET':
        data = {
            'cod_cliente': cliente.cod_cliente,
            'usuario': usuario_a_dict(cliente.usuario),
            'correo_contacto': cliente.correo_contacto,
            'puntos_fidelidad': cliente.puntos_fidelidad,
            'notas': cliente.notas
        }
        return JsonResponse(data)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            cliente.correo_contacto = data.get('correo_contacto', cliente.correo_contacto)
            cliente.puntos_fidelidad = data.get('puntos_fidelidad', cliente.puntos_fidelidad)
            cliente.notas = data.get('notas', cliente.notas)
            cliente.save()
            return JsonResponse({'mensaje': 'Cliente actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    elif request.method == 'DELETE':
        cliente.delete()
        return JsonResponse({'mensaje': 'Cliente eliminado'})
    return JsonResponse({'error': 'Método no permitido'}, status=405)
