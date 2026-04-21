from django.http import JsonResponse

def saludos_api(request):
    return JsonResponse({
        'mensaje': 'API cafeteria activa',
        'rutas': {
            'login': '/api/login/',
            'recuperar_password': '/api/recuperar-password/',
            'verificar_codigo': '/api/verificar-codigo/',
            'nueva_password': '/api/nueva-password/',
            'usuarios': '/api/usuarios/',
            'bitacora': '/api/bitacora/',
            'admin': '/admin/'
        }
    })