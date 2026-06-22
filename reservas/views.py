from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from django.db import transaction
from .models import SalaTematica, Mesa, Reserva, SalaImagen
from .serializers import SalaTematicaSerializer, MesaSerializer, ReservaSerializer, SalaImagenSerializer
from usuarios.models import Usuario, Cliente, Bitacora
from usuarios.views import decodificar_token
from pedidos.services import cancelar_preorden_por_reserva, convertir_preorden_a_pedido_por_checkin
from django.db.models import Q
from django.utils import timezone
from datetime import datetime, timedelta
from producto.models import Producto
from pedidos.models import Preorden, DetallePreorden
from reservas.notificaciones import services as notif_services
from reservas.services import (
    actualizar_estado_mesa,
    sincronizar_reservas_vencidas,
    validar_cancelacion_cliente,
    validar_horario_checkin,
)


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

class IsClienteOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.cod_rol.cod_rol in ['admin', 'cliente'])

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
        sincronizar_reservas_vencidas()
        sala = self.get_object()
        fecha_str = request.query_params.get('fecha')
        if not fecha_str:
            return Response({'error': 'Debe proporcionar una fecha (YYYY-MM-DD)'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            fecha = datetime.strptime(fecha_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({'error': 'Formato de fecha inválido. Use YYYY-MM-DD'}, status=status.HTTP_400_BAD_REQUEST)

        ahora = timezone.localtime()
        limite_reserva = ahora + timedelta(hours=3)

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
            inicio_dt = timezone.make_aware(datetime.combine(fecha, datetime.strptime(inicio, '%H:%M:%S').time()))
            bloque_fuera_anticipacion = inicio_dt <= limite_reserva
            mesas_reservadas_ids = reservas_dia.filter(hora_inicio=inicio).values_list('mesa_id', flat=True)
            
            mesas_info = []
            for m in mesas_activas:
                disponible_por_mesa = m.id not in mesas_reservadas_ids
                mesas_info.append({
                    'id': m.id,
                    'nombre': m.nombre,
                    'capacidad': m.capacidad,
                    'disponible': disponible_por_mesa and not bloque_fuera_anticipacion,
                    'estado': m.estado
                })
            
            disponibilidad.append({
                'hora_inicio': inicio,
                'hora_fin': fin,
                'bloqueado_por_anticipacion': bloque_fuera_anticipacion,
                'mensaje_bloqueo': 'Debes reservar con al menos 3 horas de anticipacion. Selecciona un horario mas tarde.' if bloque_fuera_anticipacion else '',
                'mesas': mesas_info
            })

        return Response(disponibilidad)

    @action(detail=True, methods=['get'])
    def mesas(self, request, pk=None):
        sincronizar_reservas_vencidas()
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

    def get_queryset(self):
        sincronizar_reservas_vencidas()
        return Reserva.objects.all()

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
        sincronizar_reservas_vencidas()
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

        if fecha_obj < timezone.localdate():
            return Response({'error': 'No puedes reservar en fechas pasadas'}, status=400)

        # 🔐 VALIDACIÓN HORARIO
        if hora_inicio >= hora_fin:
            return Response({'error': 'Horario inválido'}, status=400)

        try:
            hora_inicio_obj = datetime.strptime(hora_inicio, '%H:%M:%S').time()
        except ValueError:
            hora_inicio_obj = datetime.strptime(hora_inicio, '%H:%M').time()

        inicio_reserva = timezone.make_aware(datetime.combine(fecha_obj, hora_inicio_obj))
        if inicio_reserva <= timezone.localtime() + timedelta(hours=3):
            return Response(
                {'error': 'Debes reservar con al menos 3 horas de anticipacion. Selecciona un horario mas tarde para asegurar la disponibilidad de la mesa.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

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

        # 🔥 PREORDEN (intención de pedido — NO toca stock)
        # El stock se valida y descuenta recién cuando el mesero
        # marca la preorden como "con_pedido" el día de la reserva.
        productos_req = data.get('productos')
        if productos_req and isinstance(productos_req, list) and len(productos_req) > 0:
            from django.utils import timezone as tz
            estado_preorden = 'apartada' if fecha_obj == tz.localdate() else 'programada'
            total_preorden = 0
            detalles_pre = []

            for prod in productos_req:
                try:
                    producto = Producto.objects.get(id=prod.get('id'))
                except Producto.DoesNotExist:
                    reserva.delete()
                    return Response(
                        {'error': f'Producto con id {prod.get("id")} no encontrado'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                cantidad = int(prod.get('cantidad', 0))
                if cantidad <= 0:
                    reserva.delete()
                    return Response({'error': 'La cantidad debe ser mayor a 0'}, status=status.HTTP_400_BAD_REQUEST)

                if cantidad > producto.stock:
                    reserva.delete()
                    return Response(
                        {'error': f'Stock insuficiente para el producto "{producto.nombre}": disponible {producto.stock}, solicitado {cantidad}'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                subtotal = producto.precio * cantidad
                total_preorden += subtotal
                detalles_pre.append({
                    'producto': producto,
                    'cantidad': cantidad,
                    'precio_unitario': producto.precio,
                    'subtotal': subtotal,
                })

            preorden = Preorden.objects.create(
                reserva=reserva,
                cliente=cliente,
                sala=sala,
                mesa=mesa,
                total=total_preorden,
                estado=estado_preorden,
            )
            for d in detalles_pre:
                DetallePreorden.objects.create(
                    preorden=preorden,
                    producto=d['producto'],
                    cantidad=d['cantidad'],
                    precio_unitario=d['precio_unitario'],
                    subtotal=d['subtotal'],
                )


        # 🔥 BITÁCORA
        Bitacora.objects.create(
            usuario=request.user,
            accion='crear reserva',
            detalles=(
                f'Creo la reserva #{reserva.id} para {fecha} de {hora_inicio} a {hora_fin}. '
                f'Sala: {sala.nombre}. Mesa: {mesa.nombre}. Personas: {cantidad_personas}.'
            )
        )

        # Notificación in-app: reserva creada
        try:
            mensaje = f'Reserva creada: Sala {sala.nombre} - Mesa {mesa.nombre} - {fecha} {hora_inicio}'
            notif_services.crear_notificacion_reserva(reserva, 'modificacion', mensaje, enviado_por=request.user)
        except Exception:
            pass


        serializer = self.get_serializer(reserva)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # --- ACCIONES DE ESTADO ---
    
    # ──────────────────────────────────────────────────────────────────────
    # CANCELAR RESERVA
    # La cancelación de la reserva NUNCA debe bloquearse por la preorden.
    # Primero se cancela la reserva; luego se intenta cancelar la preorden.
    # ──────────────────────────────────────────────────────────────────────
    @action(detail=True, methods=['patch'])
    def cancelar(self, request, pk=None):
        from django.utils import timezone
        from django.db import transaction

        reserva = self.get_object()
        rol = request.user.cod_rol.cod_rol

        if rol not in ['cliente', 'admin', 'mesero', 'emp']:
            return Response(
                {'error': 'No tienes permiso para cancelar reservas'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if reserva.fecha < timezone.localdate():
            return Response({'error': 'No puedes cancelar reservas pasadas'}, status=400)

        if rol == 'cliente':
            if reserva.cliente.id_usuario.id_usuario != request.user.id_usuario:
                return Response({'error': 'No puedes cancelar reservas de otros'}, status=status.HTTP_403_FORBIDDEN)

        if reserva.estado not in ['pendiente', 'confirmada']:
            return Response(
                {'error': f'No se puede cancelar una reserva en estado {reserva.estado}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if rol == 'cliente':
            puede_cancelar, mensaje = validar_cancelacion_cliente(reserva)
            if not puede_cancelar:
                return Response({'error': mensaje}, status=status.HTTP_400_BAD_REQUEST)

        # 1. Cancelar la reserva (obligatorio — nunca debe fallar por la preorden)
        with transaction.atomic():
            reserva.estado = 'cancelada'
            reserva.save()
            actualizar_estado_mesa(reserva.mesa)
            Bitacora.objects.create(
                usuario=request.user,
                accion='cancelar reserva',
                detalles=f'Reserva ID {reserva.id} cancelada',
            )

        # Notificación in-app: cancelación
        try:
            mensaje = f'Tu reserva (ID {reserva.id}) ha sido cancelada'
            notif_services.crear_notificacion_reserva(reserva, 'cancelacion', mensaje, enviado_por=request.user)
        except Exception:
            pass

        # 2. Cascade: cancelar preorden asociada (aislado — no bloquea si falla)
        info_preorden = {}
        try:
            info_preorden = cancelar_preorden_por_reserva(reserva, request.user)
        except Exception as exc:
            info_preorden = {'preorden_aviso': f'Reserva cancelada. No se pudo actualizar la preorden: {exc}'}

        respuesta = {'mensaje': 'Reserva cancelada exitosamente'}
        respuesta.update(info_preorden)
        return Response(respuesta)

    # ──────────────────────────────────────────────────────────────────────
    # CONFIRMAR RESERVA (pendiente → confirmada)
    # NO toca preórdenes. Solo confirma la reserva.
    # ──────────────────────────────────────────────────────────────────────
    @action(detail=True, methods=['patch'])
    def confirmar(self, request, pk=None):
        reserva = self.get_object()

        if reserva.estado != 'pendiente':
            return Response(
                {'error': f'No se puede confirmar una reserva en estado {reserva.estado}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        reserva.estado = 'confirmada'
        reserva.save()
        reserva.mesa.estado = 'reservada'
        reserva.mesa.save()

        Bitacora.objects.create(
            usuario=request.user,
            accion='confirmar reserva',
            detalles=f'Reserva ID {reserva.id} confirmada',
        )
        # Notificación in-app: confirmación
        try:
            mensaje = f'Tu reserva (ID {reserva.id}) ha sido confirmada para {reserva.fecha} {reserva.hora_inicio}'
            notif_services.crear_notificacion_reserva(reserva, 'confirmacion', mensaje, enviado_por=request.user)
        except Exception:
            pass
        return Response({'mensaje': 'Reserva confirmada correctamente'})

    # ──────────────────────────────────────────────────────────────────────
    # CHECK-IN (confirmada → en_curso) — aquí se convierte la preorden en pedido
    # ──────────────────────────────────────────────────────────────────────
    @action(detail=True, methods=['patch'])
    def confirmar_llegada(self, request, pk=None):
        from django.db import transaction

        reserva = self.get_object()

        if reserva.estado != 'confirmada':
            return Response(
                {'error': f'Solo reservas confirmadas pueden iniciar. Estado actual: {reserva.estado}'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        puede_hacer_checkin, mensaje = validar_horario_checkin(reserva)
        if not puede_hacer_checkin:
            return Response({'error': mensaje}, status=status.HTTP_400_BAD_REQUEST)
        if reserva.mesa.estado != 'reservada':
            return Response({'error': 'La mesa no está reservada'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            reserva.estado = 'en_curso'
            reserva.save()
            reserva.mesa.estado = 'ocupada'
            reserva.mesa.save()
            Bitacora.objects.create(
                usuario=request.user,
                accion='check-in reserva',
                detalles=f'Reserva ID {reserva.id} iniciada (check-in)',
            )

        # Notificación in-app: check-in realizada
        try:
            mensaje = f'Check-in realizado para reserva ID {reserva.id}. Buen provecho.'
            notif_services.crear_notificacion_reserva(reserva, 'modificacion', mensaje, enviado_por=request.user)
        except Exception:
            pass

        # Cascade: convertir preorden en pedido real (solo aquí, en check-in)
        info_preorden = {}
        try:
            info_preorden = convertir_preorden_a_pedido_por_checkin(reserva, request.user)
        except Exception as exc:
            info_preorden = {'preorden_aviso': f'Check-in realizado. No se pudo procesar la preorden: {exc}'}

        respuesta = {'mensaje': 'Check-in realizado correctamente'}
        respuesta.update(info_preorden)
        return Response(respuesta)

    # ──────────────────────────────────────────────────────────────────────
    # LIBERAR MESA
    # ──────────────────────────────────────────────────────────────────────
    @action(detail=True, methods=['patch'])
    def liberar(self, request, pk=None):
        reserva = self.get_object()
        reserva.estado = 'liberada'
        reserva.save()
        actualizar_estado_mesa(reserva.mesa)

        info_preorden = {}
        try:
            info_preorden = cancelar_preorden_por_reserva(reserva, request.user)
        except Exception:
            pass

        respuesta = {'mensaje': 'Mesa liberada'}
        respuesta.update(info_preorden)
        return Response(respuesta)

    # ──────────────────────────────────────────────────────────────────────
    # NO ASISTIÓ
    # ──────────────────────────────────────────────────────────────────────
    @action(detail=True, methods=['patch'])
    def no_asistio(self, request, pk=None):
        reserva = self.get_object()
        reserva.estado = 'no_asistio'
        reserva.save()
        actualizar_estado_mesa(reserva.mesa)

        info_preorden = {}
        try:
            info_preorden = cancelar_preorden_por_reserva(reserva, request.user)
        except Exception:
            pass

        respuesta = {'mensaje': 'Reserva marcada como no asistió'}
        respuesta.update(info_preorden)
        return Response(respuesta)

    # ──────────────────────────────────────────────────────────────────────
    # FINALIZAR
    # ──────────────────────────────────────────────────────────────────────
    @action(detail=True, methods=['patch'])
    def finalizar(self, request, pk=None):
        reserva = self.get_object()
        if reserva.estado != 'en_curso':
            return Response(
                {'error': f'Solo se puede finalizar una reserva en curso. Estado actual: {reserva.estado}'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        reserva.estado = 'finalizada'
        reserva.save(update_fields=['estado'])
        actualizar_estado_mesa(reserva.mesa)
        return Response({'mensaje': 'Reserva finalizada y mesa liberada'})


class MesaEstadoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def patch(self, request, pk):
        from django.db.models import Q
        from pedidos.models import Pedido
        from finanzas.models import Pago

        try:
            mesa = Mesa.objects.get(id=pk)
        except Mesa.DoesNotExist:
            return Response({'error': 'La mesa no existe'}, status=status.HTTP_404_NOT_FOUND)

        nuevo_estado = request.data.get('estado')
        if nuevo_estado not in ['disponible', 'ocupada', 'reservada', 'atendida']:
            return Response({'error': f'Estado {nuevo_estado} no es válido'}, status=status.HTTP_400_BAD_REQUEST)

        estado_anterior = mesa.estado
        if estado_anterior == nuevo_estado:
            return Response({
                'id': mesa.id,
                'nombre': mesa.nombre,
                'estado': mesa.estado,
                'estado_display': mesa.get_estado_display()
            }, status=status.HTTP_200_OK)

        # Validación de transiciones
        if nuevo_estado == 'ocupada':
            # disponible -> ocupada: cuando el mesero inicia la atención
            # reservada -> ocupada: si tiene check-in en curso
            if estado_anterior in ['disponible', 'reservada']:
                # Bloquear ocupación libre si tiene reserva activa futura hoy
                reserva_futura = Reserva.objects.filter(
                    mesa=mesa,
                    fecha=timezone.localdate(),
                    estado__in=['pendiente', 'confirmada']
                ).exists()
                if reserva_futura and estado_anterior == 'disponible':
                    return Response({'error': 'La mesa tiene una reserva activa para hoy y no puede ocuparse libremente'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': f'No se puede pasar de {estado_anterior} a ocupada'}, status=status.HTTP_400_BAD_REQUEST)

        elif nuevo_estado == 'disponible':
            # ocupada -> disponible: únicamente cuando no queden deudas ni pedidos activos
            if estado_anterior == 'ocupada':
                unpaid_pedidos = Pedido.objects.filter(
                    mesa=mesa,
                    estado__in=['pendiente', 'confirmado', 'en_preparacion', 'lista']
                ).exclude(
                    pagos__estado='exitoso'
                ).exists()

                pending_payments = Pago.objects.filter(
                    estado='pendiente'
                ).filter(
                    Q(pedido__mesa=mesa) | Q(reserva__mesa=mesa) | Q(preorden__mesa=mesa)
                ).exists()

                if unpaid_pedidos or pending_payments:
                    return Response({'error': 'No se puede liberar la mesa: existen pedidos activos o pagos pendientes'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': f'No se puede liberar la mesa desde el estado {estado_anterior}'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            mesa.estado = nuevo_estado
            mesa.save()

        return Response({
            'id': mesa.id,
            'nombre': mesa.nombre,
            'estado': mesa.estado,
            'estado_display': mesa.get_estado_display()
        }, status=status.HTTP_200_OK)
