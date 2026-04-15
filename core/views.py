from django.http import JsonResponse


def saludos_api(request):
    return JsonResponse({
        'mensaje': 'API cafeteria activa',
        'rutas': {
            'usuarios': '/api/usuarios/',
            'roles': '/api/roles/',
            'admin': '/admin/'
        }
    })
