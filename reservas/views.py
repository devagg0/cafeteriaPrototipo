from rest_framework import viewsets, status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, action
from rest_framework.response import Response
from django.db.models import Q
from datetime import datetime
from .models import SalaTematica, Mesa, Reserva, SalaImagen
from .serializers import SalaTematicaSerializer, MesaSerializer, ReservaSerializer, SalaImagenSerializer
from usuarios.models import Usuario, Cliente
from usuarios.views import decodificar_token
from usuarios.models import Bitacora
# --- AUTENTICACIÓN CUSTOM ---
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        token = auth_header.split(' ')[1]
        payload = decodificar_token(token)
        if isinstance(payload, dict) and payload.get('error'):
            raise AuthenticationFailed(payload['error'])
        try:
            user = Usuario.objects.get(id_usuario=payload.get('user_id'))
            return (user, token)
        except Usuario.DoesNotExist:
            raise AuthenticationFailed('Usuario no encontrado')

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.cod_rol.cod_rol == 'admin')

class IsEmpleadoOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.cod_rol.cod_rol in ['admin', 'mesero', 'cocinero', 'emp'])

class IsAuthenticatedJWT(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user)

# --- VIEWSETS ---

class SalaTematicaViewSet(viewsets.ModelViewSet):
    queryset = SalaTematica.objects.all()
    serializer_class = SalaTematicaSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'disponibilidad', 'mesas']:
            return [IsAuthenticatedJWT()]
        return [IsAdmin()]

    @action(detail=True, methods=['patch'])
    def estado(self, request, pk=None):
        sala = self.get_object()
        # Verificar si hay reservas activas antes de deshabilitar
        if sala.habilitada and not request.data.get('habilitada', True):
            reservas_activas = Reserva.objects.filter(sala=sala, estado__in=['pendiente', 'confirmada', 'en_curso']).exists()
            if reservas_activas:
                return Response({'error': 'No se puede deshabilitar una sala con reservas activas'}, status=status.HTTP_400_BAD_REQUEST)
        
        sala.habilitada = request.data.get('habilitada', sala.habilitada)
        sala.save()
        return Response({'mensaje': 'Estado actualizado', 'habilitada': sala.habilitada})

    def destroy(self, request, *args, **kwargs):
        sala = self.get_object()
        reservas_activas = Reserva.objects.filter(sala=sala, estado__in=['pendiente', 'confirmada', 'en_curso']).exists()
        if reservas_activas:
            return Response({'error': 'No se puede eliminar una sala con reservas activas'}, status=status.HTTP_400_BAD_REQUEST)
        sala.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['post'], parser_classes=[MultiPartParser, FormParser])
    def subir_galeria(self, request, pk=None):
        sala = self.get_object()
        imagenes = request.FILES.getlist('galeria')
        for img in imagenes:
            SalaImagen.objects.create(sala=sala, imagen=img)
        return Response({'mensaje': 'Imágenes subidas correctamente'}, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def eliminar_imagen(self, request, pk=None):
        sala = self.get_object()
        imagen_id = request.data.get('imagen_id')
        try:
            imagen = SalaImagen.objects.get(id=imagen_id, sala=sala)
            imagen.imagen.delete(save=False) # Eliminar archivo del filesystem
            imagen.delete()
            return Response({'mensaje': 'Imagen eliminada'}, status=status.HTTP_200_OK)
        except SalaImagen.DoesNotExist:
            return Response({'error': 'Imagen no encontrada'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['get'])
    def disponibilidad(self, request, pk=None):
        sala = self.get_object()
        fecha_str = request.query_params.get('fecha')
        if not fecha_str:
            return Response({'error': 'Debe proporcionar una fecha (YYYY-MM-DD)'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            fecha = datetime.strptime(fecha_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({'error': 'Formato de fecha inválido. Use YYYY-MM-DD'}, status=status.HTTP_400_BAD_REQUEST)

        # Horarios fijos
        horarios = [
            ("10:00:00", "11:30:00"),
            ("11:30:00", "13:00:00"),
            ("13:00:00", "14:30:00"),
            ("14:30:00", "16:00:00"),
            ("16:00:00", "17:30:00"),
            ("17:30:00", "19:00:00"),
            ("19:00:00", "20:30:00"),
            ("20:30:00", "22:00:00"),
        ]

        mesas_activas = Mesa.objects.filter(sala=sala, activa=True)
        reservas_dia = Reserva.objects.filter(sala=sala, fecha=fecha, estado__in=['pendiente', 'confirmada', 'en_curso'])

        disponibilidad = []
        for inicio, fin in horarios:
            mesas_reservadas_ids = reservas_dia.filter(hora_inicio=inicio).values_list('mesa_id', flat=True)
            
            mesas_info = []
            for m in mesas_activas:
                mesas_info.append({
                    'id': m.id,
                    'nombre': m.nombre,
                    'capacidad': m.capacidad,
                    'disponible': (m.id not in mesas_reservadas_ids),
                    'estado': m.estado
                })
            
            disponibilidad.append({
                'hora_inicio': inicio,
                'hora_fin': fin,
                'mesas': mesas_info
            })

        return Response(disponibilidad)

    @action(detail=True, methods=['get'])
    def mesas(self, request, pk=None):
        sala = self.get_object()
        mesas = Mesa.objects.filter(sala=sala, activa=True)
        serializer = MesaSerializer(mesas, many=True)
        return Response(serializer.data)


class MesaViewSet(viewsets.ModelViewSet):
    queryset = Mesa.objects.all()
    serializer_class = MesaSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdmin]

    def destroy(self, request, *args, **kwargs):
        mesa = self.get_object()
        # Evitar eliminar mesas con reservas activas
        reservas_activas = Reserva.objects.filter(mesa=mesa, estado__in=['pendiente', 'confirmada', 'en_curso']).exists()
        if reservas_activas:
            return Response({'error': 'No se puede eliminar una mesa con reservas activas'}, status=status.HTTP_400_BAD_REQUEST)
        # Soft delete
        mesa.activa = False
        mesa.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ReservaViewSet(viewsets.ModelViewSet):
    queryset = Reserva.objects.all()
    serializer_class = ReservaSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):

    # CLIENTE
        if self.action in ['create', 'mis_reservas', 'cancelar']:
            return [IsAuthenticatedJWT()]

    # EMPLEADO + ADMIN
        if self.action in [
        'list',
        'retrieve',
        'confirmar',
        'confirmar_llegada',
        'liberar',
        'no_asistio',
        'finalizar'
    ]:
         return [IsEmpleadoOrAdmin()]

    # SOLO ADMIN
        return [IsAdmin()]

    @action(detail=False, methods=['get'])
    def mis_reservas(self, request):
        if request.user.cod_rol.cod_rol != 'cliente':
            return Response({'error': 'Solo los clientes tienen "mis reservas"'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            cliente = Cliente.objects.get(id_usuario=request.user)
            reservas = Reserva.objects.filter(cliente=cliente).order_by('-fecha', '-hora_inicio')
            serializer = self.get_serializer(reservas, many=True)
            return Response(serializer.data)
        except Cliente.DoesNotExist:
            return Response({'error': 'Perfil de cliente no encontrado'}, status=status.HTTP_404_NOT_FOUND)

    def create(self, request, *args, **kwargs):
        data = request.data
        if request.user.cod_rol.cod_rol != 'cliente':
            return Response({'error': 'Solo los clientes pueden hacer reservas web'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            cliente = Cliente.objects.get(id_usuario=request.user)
        except Cliente.DoesNotExist:
            return Response({'error': 'Perfil de cliente no encontrado'}, status=status.HTTP_400_BAD_REQUEST)

        sala_id = data.get('sala')
        mesa_id = data.get('mesa')
        fecha = data.get('fecha')
        hora_inicio = data.get('hora_inicio')
        hora_fin = data.get('hora_fin')
        cantidad_personas = data.get('cantidad_personas')

        # 🔐 VALIDACIÓN FECHA
        from django.utils import timezone
        from datetime import datetime

        try:
            fecha_obj = datetime.strptime(fecha, "%Y-%m-%d").date()
        except:
            return Response({'error': 'Formato de fecha inválido'}, status=400)

        if fecha_obj < timezone.now().date():
            return Response({'error': 'No puedes reservar en fechas pasadas'}, status=400)

        # 🔐 VALIDACIÓN HORARIO
        if hora_inicio >= hora_fin:
            return Response({'error': 'Horario inválido'}, status=400)

        try:
            sala = SalaTematica.objects.get(id=sala_id)
            mesa = Mesa.objects.get(id=mesa_id, sala=sala)
        except (SalaTematica.DoesNotExist, Mesa.DoesNotExist):
            return Response({'error': 'Sala o Mesa no válidas'}, status=status.HTTP_400_BAD_REQUEST)

        if not sala.habilitada:
            return Response({'error': 'La sala está deshabilitada'}, status=status.HTTP_400_BAD_REQUEST)
        if not mesa.activa:
            return Response({'error': 'La mesa no está activa'}, status=status.HTTP_400_BAD_REQUEST)
        if int(cantidad_personas) > mesa.capacidad:
            return Response({'error': 'La cantidad de personas excede la capacidad de la mesa'}, status=status.HTTP_400_BAD_REQUEST)

        # Validar cruce de reservas
        cruce = Reserva.objects.filter(
            mesa=mesa,
            fecha=fecha,
            estado__in=['pendiente', 'confirmada', 'en_curso']
        ).filter(
            hora_inicio__lt=hora_fin,
            hora_fin__gt=hora_inicio
        ).exists()

        if cruce:
            return Response({'error': 'La mesa ya está reservada en este horario'}, status=status.HTTP_400_BAD_REQUEST)

        reserva = Reserva.objects.create(
            cliente=cliente,
            sala=sala,
            mesa=mesa,
            fecha=fecha,
            hora_inicio=hora_inicio,
            hora_fin=hora_fin,
            cantidad_personas=cantidad_personas,
            estado='pendiente'
        )

        # 🔥 BITÁCORA
        Bitacora.objects.create(
            usuario=request.user,
            accion='crear reserva',
            detalles=f'Reserva ID {reserva.id} - Sala {sala.nombre} - Mesa {mesa.nombre}'
        )


        serializer = self.get_serializer(reserva)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # --- ACCIONES DE ESTADO ---
    
    @action(detail=True, methods=['patch'])
    def cancelar(self, request, pk=None):
        reserva = self.get_object()
        
        from django.utils import timezone

        # 🔐 VALIDAR FECHA
        if reserva.fecha < timezone.now().date():
            return Response({'error': 'No puedes cancelar reservas pasadas'}, status=400)
        
        if request.user.cod_rol.cod_rol == 'cliente':
            # Validar que el cliente solo cancele sus reservas
            if reserva.cliente.id_usuario.id_usuario != request.user.id_usuario:
                return Response({'error': 'No puedes cancelar reservas de otros'}, status=status.HTTP_403_FORBIDDEN)
        
        if reserva.estado not in ['pendiente', 'confirmada']:
            return Response({'error': f'No se puede cancelar una reserva en estado {reserva.estado}'}, status=status.HTTP_400_BAD_REQUEST)
        
        
        # 🔥 CANCELAR
        reserva.estado = 'cancelada'
        reserva.save()

        actualizar_estado_mesa(reserva.mesa)
        
        # 🔥 BITÁCORA
        Bitacora.objects.create(
            usuario=request.user,
            accion='cancelar reserva',
            detalles=f'Reserva ID {reserva.id} cancelada'
        )
        
        return Response({'mensaje': 'Reserva cancelada exitosamente'})
    @action(detail=True, methods=['patch'])
    def confirmar(self, request, pk=None):

     reserva = self.get_object()

    # VALIDAR ESTADO
     if reserva.estado != 'pendiente':
        return Response({
            'error': f'No se puede confirmar una reserva en estado {reserva.estado}'
        }, status=status.HTTP_400_BAD_REQUEST)

    # VALIDAR MESA
    

    # CAMBIAR ESTADOS
     reserva.estado = 'confirmada'
     reserva.save()

     reserva.mesa.estado = 'reservada'
     reserva.mesa.save()

    # BITÁCORA
     Bitacora.objects.create(
        usuario=request.user,
        accion='confirmar reserva',
        detalles=f'Reserva ID {reserva.id} confirmada'
    )

     return Response({
        'mensaje': 'Reserva confirmada correctamente'
    })

    @action(detail=True, methods=['patch'])
    def confirmar_llegada(self, request, pk=None):

     reserva = self.get_object()

    # VALIDAR ESTADO
     if reserva.estado != 'confirmada':
        return Response({
            'error': f'Solo reservas confirmadas pueden iniciar. Estado actual: {reserva.estado}'
        }, status=status.HTTP_400_BAD_REQUEST)

    # VALIDAR MESA
     if reserva.mesa.estado != 'reservada':
        return Response({
            'error': 'La mesa no está reservada'
        }, status=status.HTTP_400_BAD_REQUEST)

    # CAMBIAR ESTADO RESERVA
     reserva.estado = 'en_curso'
     reserva.save()

    # CAMBIAR ESTADO MESA
     reserva.mesa.estado = 'ocupada'
     reserva.mesa.save()

    # BITÁCORA
     Bitacora.objects.create(
        usuario=request.user,
        accion='check-in reserva',
        detalles=f'Reserva ID {reserva.id} iniciada'
    )

     return Response({
        'mensaje': 'Check-in realizado correctamente'
    })

    @action(detail=True, methods=['patch'])
    def liberar(self, request, pk=None):

        reserva = self.get_object()

        reserva.estado = 'liberada'
        reserva.save()

        actualizar_estado_mesa(reserva.mesa)

        return Response({
          'mensaje': 'Mesa liberada'
    })

    @action(detail=True, methods=['patch'])
    def no_asistio(self, request, pk=None):

        reserva = self.get_object()

        reserva.estado = 'no_asistio'
        reserva.save()

        actualizar_estado_mesa(reserva.mesa)

        return Response({
            'mensaje': 'Reserva marcada como no asistió'
    })

    @action(detail=True, methods=['patch'])
    def finalizar(self, request, pk=None):
        reserva = self.get_object()
        reserva.estado = 'finalizada'
        reserva.save()
        return Response({'mensaje': 'Reserva finalizada'})

def actualizar_estado_mesa(mesa):

    reservas_activas = Reserva.objects.filter(
        mesa=mesa,
        estado__in=['pendiente', 'confirmada', 'en_curso']
    ).exists()

    if reservas_activas:

        reserva_en_curso = Reserva.objects.filter(
            mesa=mesa,
            estado='en_curso'
        ).exists()

        if reserva_en_curso:
            mesa.estado = 'ocupada'
        else:
            mesa.estado = 'reservada'

    else:
        mesa.estado = 'disponible'

    mesa.save()
