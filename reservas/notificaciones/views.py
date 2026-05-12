from django.http import JsonResponse

from usuarios.models import Cliente

from reservas.models import (
    NotificacionReserva,
    Reserva
)


def historial_notificaciones(request):

    notificaciones = NotificacionReserva.objects.select_related(
        'reserva__cliente__id_usuario'
    ).all().order_by('-enviada_en')

    data = []

    for n in notificaciones:

        data.append({
            'id': n.id,
            'cliente': n.reserva.cliente.id_usuario.nombre,
            'tipo': n.tipo,
            'mensaje': n.mensaje,
            'fecha': str(n.enviada_en)
        })

    return JsonResponse(data, safe=False)


def enviar_notificacion_manual(request):

    try:

        reserva = Reserva.objects.filter(
          estado='confirmada'
     ).order_by('-id').first()

        if not reserva:

            return JsonResponse({
                'error': 'No existen reservas'
            }, status=404)

        notificacion = NotificacionReserva.objects.create(
            reserva=reserva,
            tipo='recordatorio',
            mensaje='Recordatorio de reserva enviado manualmente'
        )

        return JsonResponse({
            'mensaje': 'Notificación registrada correctamente',
            'id_notificacion': notificacion.id
        })

    except Exception as e:

        return JsonResponse({
            'error': str(e)
        }, status=500)


def mis_notificaciones(request, cliente_id):

    try:

        cliente = Cliente.objects.get(
            cod_cliente=cliente_id
        )

        notificaciones = NotificacionReserva.objects.filter(
            reserva__cliente=cliente
        ).order_by('-enviada_en')

        data = []

        for n in notificaciones:

            data.append({
                'id': n.id,
                'tipo': n.tipo,
                'mensaje': n.mensaje,
                'fecha': str(n.enviada_en)
            })

        return JsonResponse(data, safe=False)

    except Cliente.DoesNotExist:

        return JsonResponse({
            'error': 'Cliente no encontrado'
        }, status=404)

    except Exception as e:

        return JsonResponse({
            'error': str(e)
        }, status=500)