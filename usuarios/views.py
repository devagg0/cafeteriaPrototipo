import json
import hashlib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Rol, Usuario, Empleado, Cliente


def hashear_contrasena(contrasena):
    """Hashea una contraseña con SHA-256"""
    return hashlib.sha256(contrasena.encode()).hexdigest()


@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            correo = data.get('correo')
            contrasena = data.get('contrasena')
            if not correo or not contrasena:
                return JsonResponse({'error': 'Campos requeridos: correo, contrasena'}, status=400)
            try:
                usuario = Usuario.objects.get(correo=correo, contrasena=hashear_contrasena(contrasena))
                return JsonResponse({
                    'mensaje': 'Inicio de sesión exitoso',
                    'id_usuario': usuario.id_usuario,
                    'nombre': usuario.nombre,
                    'rol': usuario.cod_rol.nombre
                })
            except Usuario.DoesNotExist:
                return JsonResponse({'error': 'Credenciales inválidas'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
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
        usuarios = Usuario.objects.all()
        data = [usuario_a_dict(u) for u in usuarios]
        return JsonResponse(data, safe=False)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            nombre = data.get('nombre')
            correo = data.get('correo')
            contrasena = data.get('contrasena')
            cod_rol = data.get('cod_rol')
            if not all([nombre, correo, contrasena, cod_rol]):
                return JsonResponse({'error': 'Campos requeridos: nombre, correo, contrasena, cod_rol'}, status=400)
            if Usuario.objects.filter(correo=correo).exists():
                return JsonResponse({'error': 'Correo ya registrado'}, status=400)
            try:
                rol = Rol.objects.get(cod_rol=cod_rol)
            except Rol.DoesNotExist:
                return JsonResponse({'error': 'Rol no encontrado'}, status=400)
            usuario = Usuario.objects.create(
                nombre=nombre,
                correo=correo,
                contrasena=hashear_contrasena(contrasena),
                cod_rol=rol
            )
            return JsonResponse({'mensaje': 'Usuario creado', 'id_usuario': usuario.id_usuario}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def detalle_usuario(request, user_id):
    try:
        usuario = Usuario.objects.get(id_usuario=user_id)
    except Usuario.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
    if request.method == 'GET':
        return JsonResponse(usuario_a_dict(usuario))
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            usuario.nombre = data.get('nombre', usuario.nombre)
            usuario.correo = data.get('correo', usuario.correo)
            if 'contrasena' in data:
                usuario.contrasena = hashear_contrasena(data.get('contrasena'))
            usuario.save()
            return JsonResponse({'mensaje': 'Usuario actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    elif request.method == 'DELETE':
        usuario.delete()
        return JsonResponse({'mensaje': 'Usuario eliminado'})
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def asignar_rol(request, user_id):
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
            'usuario': usuario_a_dict(e.id_usuario),
            'cargo': e.cargo,
            'turno': e.turno,
        } for e in empleados]
        return JsonResponse(data, safe=False)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            cod_empleado = data.get('cod_empleado')
            user_id = data.get('id_usuario')
            cargo = data.get('cargo')
            turno = data.get('turno')
            if not all([cod_empleado, user_id, cargo, turno]):
                return JsonResponse({'error': 'Campos requeridos: cod_empleado, id_usuario, cargo, turno'}, status=400)
            try:
                usuario = Usuario.objects.get(id_usuario=user_id)
            except Usuario.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=400)
            if hasattr(usuario, 'empleado'):
                return JsonResponse({'error': 'Usuario ya es empleado'}, status=400)
            empleado = Empleado.objects.create(
                cod_empleado=cod_empleado,
                id_usuario=usuario,
                cargo=cargo,
                turno=turno
            )
            return JsonResponse({'mensaje': 'Empleado creado', 'cod_empleado': empleado.cod_empleado}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
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
            'usuario': usuario_a_dict(empleado.id_usuario),
            'cargo': empleado.cargo,
            'turno': empleado.turno,
        }
        return JsonResponse(data)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            empleado.cargo = data.get('cargo', empleado.cargo)
            empleado.turno = data.get('turno', empleado.turno)
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
            'usuario': usuario_a_dict(c.id_usuario),
            'telefono': c.telefono,
            'direccion': c.direccion,
        } for c in clientes]
        return JsonResponse(data, safe=False)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            cod_cliente = data.get('cod_cliente')
            user_id = data.get('id_usuario')
            telefono = data.get('telefono')
            direccion = data.get('direccion')
            if not all([cod_cliente, user_id, telefono, direccion]):
                return JsonResponse({'error': 'Campos requeridos: cod_cliente, id_usuario, telefono, direccion'}, status=400)
            try:
                usuario = Usuario.objects.get(id_usuario=user_id)
            except Usuario.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=400)
            if hasattr(usuario, 'cliente'):
                return JsonResponse({'error': 'Usuario ya es cliente'}, status=400)
            cliente = Cliente.objects.create(
                cod_cliente=cod_cliente,
                id_usuario=usuario,
                telefono=telefono,
                direccion=direccion
            )
            return JsonResponse({'mensaje': 'Cliente creado', 'cod_cliente': cliente.cod_cliente}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
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
            'usuario': usuario_a_dict(cliente.id_usuario),
            'telefono': cliente.telefono,
            'direccion': cliente.direccion,
        }
        return JsonResponse(data)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            cliente.telefono = data.get('telefono', cliente.telefono)
            cliente.direccion = data.get('direccion', cliente.direccion)
            cliente.save()
            return JsonResponse({'mensaje': 'Cliente actualizado'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)
    elif request.method == 'DELETE':
        cliente.delete()
        return JsonResponse({'mensaje': 'Cliente eliminado'})
    return JsonResponse({'error': 'Método no permitido'}, status=405)
