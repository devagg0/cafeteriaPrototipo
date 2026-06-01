from django.db import transaction
from reservas.models import NotificacionReserva, Reserva
from usuarios.models import Cliente, Bitacora, Usuario


def crear_notificacion_reserva(reserva: Reserva, tipo: str, mensaje: str, enviado_por: Usuario = None) -> NotificacionReserva:
	"""Crea una notificación in-app asociada a una reserva."""
	with transaction.atomic():
		n = NotificacionReserva.objects.create(
			reserva=reserva,
			tipo=tipo,
			mensaje=mensaje,
			enviado_por=enviado_por
		)
		Bitacora.objects.create(
			usuario=enviado_por if enviado_por is not None else reserva.cliente.id_usuario,
			accion='crear notificacion',
			detalles=f'Notificacion ID {n.id} para Reserva ID {reserva.id} - tipo {tipo}'
		)
		return n


def listar_notificaciones_para_cliente(usuario):
	"""Devuelve queryset de notificaciones para el cliente asociado al `usuario`."""
	try:
		cliente = Cliente.objects.get(id_usuario=usuario)
	except Cliente.DoesNotExist:
		return NotificacionReserva.objects.none()
	return NotificacionReserva.objects.filter(reserva__cliente=cliente).order_by('-enviada_en')


def contar_no_leidas_para_usuario(usuario) -> int:
	try:
		cliente = Cliente.objects.get(id_usuario=usuario)
	except Cliente.DoesNotExist:
		return 0
	return NotificacionReserva.objects.filter(reserva__cliente=cliente, leido=False).count()


def marcar_notificacion_leida(notificacion: NotificacionReserva, usuario) -> bool:
	"""Marca como leída si pertenece al usuario o si el usuario es admin."""
	# Si es admin puede marcar cualquier notificación
	try:
		if usuario.cod_rol.cod_rol == 'admin':
			notificacion.leido = True
			notificacion.save()
			return True
	except Exception:
		pass

	# Verificar propiedad
	try:
		cliente = Cliente.objects.get(id_usuario=usuario)
	except Cliente.DoesNotExist:
		return False

	if notificacion.reserva.cliente == cliente:
		notificacion.leido = True
		notificacion.save()
		return True
	return False


def enviar_notificacion_manual(reserva: Reserva, tipo: str, mensaje: str, enviado_por: Usuario = None) -> NotificacionReserva:
	"""Alias para crear notificación desde acciones manuales de admin."""
	return crear_notificacion_reserva(reserva, tipo, mensaje, enviado_por=enviado_por)
