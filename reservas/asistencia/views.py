from django.http import JsonResponse
from reservas.models import Reserva


def reservas_pendientes(request):

    reservas = Reserva.objects.filter(
        estado='confirmada'
    ).select_related(
        'cliente__id_usuario',
        'mesa',
        'sala'
    )

    data = []

    for reserva in reservas:
        data.append({
            'id': reserva.id,
            'cliente': reserva.cliente.id_usuario.nombre,
            'sala': reserva.sala.nombre,
            'mesa': reserva.mesa.nombre,
            'fecha': str(reserva.fecha),
            'hora_inicio': str(reserva.hora_inicio),
            'estado': reserva.estado
        })

    return JsonResponse(data, safe=False)


def checkin_reserva(request, reserva_id):

    try:
        reserva = Reserva.objects.get(id=reserva_id)

        if reserva.estado != 'confirmada':
            return JsonResponse({
                'error': 'Solo reservas confirmadas pueden iniciar'
            }, status=400)

        reserva.estado = 'en_curso'
        reserva.save()

        reserva.mesa.estado = 'ocupada'
        reserva.mesa.save()

        return JsonResponse({
            'mensaje': 'Check-in realizado correctamente'
        })

    except Reserva.DoesNotExist:
        return JsonResponse({
            'error': 'Reserva no encontrada'
        }, status=404)


def marcar_no_asistio(request, reserva_id):

    try:
        reserva = Reserva.objects.get(id=reserva_id)

        reserva.estado = 'no_asistio'
        reserva.save()

        reserva.mesa.estado = 'disponible'
        reserva.mesa.save()

        return JsonResponse({
            'mensaje': 'Reserva marcada como no asistió'
        })

    except Reserva.DoesNotExist:
        return JsonResponse({
            'error': 'Reserva no encontrada'
        }, status=404)