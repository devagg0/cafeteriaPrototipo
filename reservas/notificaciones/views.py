from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from reservas.models import NotificacionReserva, Reserva
from reservas.notificaciones import services as notif_services
from reservas.views import JWTAuthentication


class HistorialNotificacionesView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        # Solo admin puede listar todas
        if not request.user or getattr(request.user, 'cod_rol', None) is None or request.user.cod_rol.cod_rol != 'admin':
            return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)

        qs = NotificacionReserva.objects.select_related('reserva__cliente__id_usuario').all().order_by('-enviada_en')
        data = []
        for n in qs:
            data.append({
                'id': n.id,
                'cliente': n.reserva.cliente.id_usuario.nombre,
                'tipo': n.tipo,
                'mensaje': n.mensaje,
                'leido': n.leido,
                'fecha': str(n.enviada_en)
            })
        return Response(data)


class MisNotificacionesView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        # Cliente autenticado
        if not request.user:
            return Response({'error': 'Sin autenticar'}, status=status.HTTP_401_UNAUTHORIZED)

        qs = notif_services.listar_notificaciones_para_cliente(request.user)
        data = []
        for n in qs:
            data.append({
                'id': n.id,
                'tipo': n.tipo,
                'mensaje': n.mensaje,
                'leido': n.leido,
                'fecha': str(n.enviada_en)
            })
        return Response(data)


class ContadorNoLeidasView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        if not request.user:
            return Response({'count': 0})
        count = notif_services.contar_no_leidas_para_usuario(request.user)
        return Response({'count': count})


class MarcarLeidoView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request, pk=None):
        try:
            n = NotificacionReserva.objects.get(id=pk)
        except NotificacionReserva.DoesNotExist:
            return Response({'error': 'Notificación no encontrada'}, status=status.HTTP_404_NOT_FOUND)

        ok = notif_services.marcar_notificacion_leida(n, request.user)
        if not ok:
            return Response({'error': 'No autorizado para marcar'}, status=status.HTTP_403_FORBIDDEN)
        return Response({'mensaje': 'Marcado como leído'})


class EnviarNotificacionManualView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        # Solo admin
        if not request.user or getattr(request.user, 'cod_rol', None) is None or request.user.cod_rol.cod_rol != 'admin':
            return Response({'error': 'No autorizado'}, status=status.HTTP_403_FORBIDDEN)

        reserva_id = request.data.get('reserva_id')
        tipo = request.data.get('tipo', 'recordatorio')
        mensaje = request.data.get('mensaje', 'Notificación manual')

        if not reserva_id:
            return Response({'error': 'Falta reserva_id'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reserva = Reserva.objects.get(id=reserva_id)
        except Reserva.DoesNotExist:
            return Response({'error': 'Reserva no encontrada'}, status=status.HTTP_404_NOT_FOUND)

        n = notif_services.enviar_notificacion_manual(reserva, tipo, mensaje, enviado_por=request.user)
        return Response({'mensaje': 'Notificación registrada', 'id_notificacion': n.id}, status=status.HTTP_201_CREATED)