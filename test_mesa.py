from reservas.models import SalaTematica
from django.db.models import Sum

sala = SalaTematica.objects.first()
existing_mesas = sala.mesas.all()
capacidad_usada = existing_mesas.aggregate(Sum('capacidad'))['capacidad__sum'] or 0

print(f"Sala ID: {sala.id}")
print(f"Capacidad Total Sala: {sala.capacidad_total}")
print(f"Capacidad Usada: {capacidad_usada}")
