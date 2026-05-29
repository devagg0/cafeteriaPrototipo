from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reservas', '0008_preorden_reserva_cliente'),
    ]

    operations = [
        migrations.AlterField(
            model_name='preorden',
            name='estado',
            field=models.CharField(
                choices=[
                    ('programada', 'Programada'),
                    ('apartada', 'Apartada'),
                    ('con_pedido', 'Con Pedido'),
                    ('sin_stock', 'Sin Stock'),
                    ('cancelada', 'Cancelada'),
                    ('entregada', 'Entregada'),
                ],
                default='programada',
                max_length=20,
            ),
        ),
    ]
