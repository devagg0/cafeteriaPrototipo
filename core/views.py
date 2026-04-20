from django.http import JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
from usuarios.models import Usuario
def saludos_api(request):
    return JsonResponse({
        'mensaje': 'API cafeteria activa',
        'rutas': {
            'usuarios': '/api/usuarios/',
            'roles': '/api/roles/',
            'admin': '/admin/'
        }
    })
