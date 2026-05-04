from django.core.management.base import BaseCommand
from reservas.models import SalaTematica

class Command(BaseCommand):
    help = 'Crea las 8 salas temáticas iniciales'

    def handle(self, *args, **kwargs):
        salas = [
            'Romántica',
            'Coworking',
            'Celda',
            'Enfermería',
            'Ochentera',
            'Blanco y negro',
            'LED',
            'Sala 8'
        ]

        for nombre in salas:
            sala, created = SalaTematica.objects.get_or_create(
                nombre=nombre,
                defaults={
                    'descripcion': f'Descripción de la sala {nombre}',
                    'capacidad_total': 20,
                    'habilitada': True
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'Sala creada: {nombre}'))
            else:
                self.stdout.write(self.style.WARNING(f'La sala ya existe: {nombre}'))
        
        self.stdout.write(self.style.SUCCESS('Proceso de seed finalizado.'))
