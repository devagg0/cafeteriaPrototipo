from rest_framework import serializers
from django.utils import timezone
from datetime import timedelta

from ..models import DetallePedido, Pedido
from reservas.models import Reserva


def reserva_relacionada_pedido(pedido):
    reserva = getattr(pedido, 'reserva', None)
    if reserva:
        return reserva

    sala = getattr(pedido, 'sala', None)
    mesa = getattr(pedido, 'mesa', None)
    created_at = getattr(pedido, 'created_at', None)
    if not sala or not mesa or not created_at:
        return None

    fecha_hora = timezone.localtime(created_at)
    return (
        Reserva.objects.select_related('cliente__id_usuario', 'sala', 'mesa')
        .filter(
            sala=sala,
            mesa=mesa,
            fecha=fecha_hora.date(),
            hora_inicio__lte=fecha_hora.time(),
            hora_fin__gte=fecha_hora.time(),
            estado__in=['confirmada', 'en_curso', 'finalizada', 'liberada'],
        )
        .order_by('-creada_en')
        .first()
    )


def nombre_cliente_pedido(pedido):
    reserva = reserva_relacionada_pedido(pedido)
    cliente = getattr(reserva, 'cliente', None)
    usuario_cliente = getattr(cliente, 'id_usuario', None)
    if usuario_cliente:
        return usuario_cliente.nombre
    cliente_directo = getattr(pedido, 'cliente', None)
    if cliente_directo and cliente_directo.id_usuario:
        return cliente_directo.id_usuario.nombre
    return pedido.nombre_cliente or 'Cliente presencial'


def origen_pedido(pedido):
    reserva = getattr(pedido, 'reserva', None)
    if not reserva:
        return 'Pedido directo'

    preordenes = list(getattr(reserva, 'preordenes', []).all()) if hasattr(getattr(reserva, 'preordenes', None), 'all') else []
    if preordenes:
        return 'Preorden'
    return 'Reserva'


def es_usuario_atencion(usuario):
    cod_rol = getattr(getattr(usuario, 'cod_rol', None), 'cod_rol', None)
    return cod_rol in ['mesero', 'emp']


def nombre_mesero_pedido(pedido):
    reserva = getattr(pedido, 'reserva', None)
    preordenes = list(getattr(reserva, 'preordenes', []).all()) if hasattr(getattr(reserva, 'preordenes', None), 'all') else []
    for preorden in preordenes:
        usuario_mesero = getattr(preorden, 'usuario_mesero', None)
        if usuario_mesero and es_usuario_atencion(usuario_mesero):
            return getattr(usuario_mesero, 'nombre', None)

    usuario = getattr(pedido, 'usuario', None)
    if usuario and es_usuario_atencion(usuario):
        return getattr(usuario, 'nombre', None)
    return 'Sin mesero asignado'


def ubicacion_pedido(pedido):
    reserva = getattr(pedido, 'reserva', None)
    sala = getattr(pedido, 'sala', None) or getattr(reserva, 'sala', None)
    mesa = getattr(pedido, 'mesa', None) or getattr(reserva, 'mesa', None)

    partes = []
    if sala:
        partes.append(getattr(sala, 'nombre', str(sala)))
    if mesa:
        partes.append(getattr(mesa, 'nombre', str(mesa)))
    return ' - '.join(partes) if partes else None


class HistorialPedidoSerializer(serializers.ModelSerializer):
    numero_pedido = serializers.SerializerMethodField()
    cliente = serializers.SerializerMethodField()
    origen = serializers.SerializerMethodField()
    atendido_por = serializers.SerializerMethodField()
    ubicacion = serializers.SerializerMethodField()
    fecha = serializers.SerializerMethodField()

    class Meta:
        model = Pedido
        fields = (
            'id',
            'numero_pedido',
            'cliente',
            'origen',
            'atendido_por',
            'ubicacion',
            'fecha',
            'estado',
            'total',
        )

    def get_numero_pedido(self, obj):
        return f'PED-{obj.id:03d}'

    def get_fecha(self, obj):
        return obj.created_at.date().isoformat()

    def get_cliente(self, obj):
        return nombre_cliente_pedido(obj)

    def get_origen(self, obj):
        return origen_pedido(obj)

    def get_atendido_por(self, obj):
        return nombre_mesero_pedido(obj)

    def get_ubicacion(self, obj):
        return ubicacion_pedido(obj)


class HistorialDetalleSerializer(serializers.ModelSerializer):
    producto = serializers.ReadOnlyField(source='producto.nombre')
    producto_id = serializers.ReadOnlyField(source='producto.id')
    producto_categoria = serializers.ReadOnlyField(source='producto.categoria.nombre')
    stock_disponible = serializers.SerializerMethodField()

    class Meta:
        model = DetallePedido
        fields = ('producto_id', 'producto', 'producto_categoria', 'cantidad', 'precio_unitario', 'subtotal', 'observaciones', 'stock_disponible')

    def get_stock_disponible(self, obj):
        return obj.producto.stock + obj.cantidad


class HistorialPedidoDetailSerializer(serializers.ModelSerializer):
    numero_pedido = serializers.SerializerMethodField()
    cliente = serializers.SerializerMethodField()
    origen = serializers.SerializerMethodField()
    atendido_por = serializers.SerializerMethodField()
    ubicacion = serializers.SerializerMethodField()
    fecha = serializers.SerializerMethodField()
    detalle = HistorialDetalleSerializer(source='detalles', many=True, read_only=True)
    editable = serializers.SerializerMethodField()
    edicion_bloqueada_motivo = serializers.SerializerMethodField()
    fecha_limite_edicion = serializers.SerializerMethodField()

    class Meta:
        model = Pedido
        fields = (
            'id',
            'numero_pedido',
            'cliente',
            'origen',
            'atendido_por',
            'ubicacion',
            'fecha',
            'estado',
            'total',
            'detalle',
            'editable',
            'edicion_bloqueada_motivo',
            'fecha_limite_edicion',
        )

    def get_numero_pedido(self, obj):
        return f'PED-{obj.id:03d}'

    def get_fecha(self, obj):
        return obj.created_at.date().isoformat()

    def get_cliente(self, obj):
        return nombre_cliente_pedido(obj)

    def get_origen(self, obj):
        return origen_pedido(obj)

    def get_atendido_por(self, obj):
        return nombre_mesero_pedido(obj)

    def get_ubicacion(self, obj):
        return ubicacion_pedido(obj)

    def get_editable(self, obj):
        return pedido_es_editable(obj)[0]

    def get_edicion_bloqueada_motivo(self, obj):
        return pedido_es_editable(obj)[1]

    def get_fecha_limite_edicion(self, obj):
        return (obj.created_at + timedelta(minutes=5)).isoformat()


def pedido_es_editable(pedido):
    if pedido.estado not in ['pendiente', 'confirmado']:
        return False, 'El pedido ya fue tomado por cocina o finalizado.'
    if timezone.now() > pedido.created_at + timedelta(minutes=5):
        return False, 'El tiempo de edicion de 5 minutos ya termino.'
    return True, ''
