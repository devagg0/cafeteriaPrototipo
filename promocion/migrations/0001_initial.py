from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ('producto', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Promocion',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                ('codigo', models.CharField(max_length=30, unique=True)),
                ('nombre', models.CharField(max_length=100)),
                ('descripcion', models.TextField(blank=True, null=True)),
                (
                    'tipo_descuento',
                    models.CharField(
                        choices=[
                            ('porcentaje', 'Porcentaje'),
                            ('monto_fijo', 'Monto Fijo'),
                        ],
                        max_length=15,
                    ),
                ),
                ('valor_descuento', models.DecimalField(decimal_places=2, max_digits=10)),
                ('fecha_inicio', models.DateField()),
                ('fecha_fin', models.DateField()),
                ('activa', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'categorias',
                    models.ManyToManyField(
                        blank=True,
                        related_name='promociones',
                        to='producto.categoria',
                    ),
                ),
                (
                    'productos',
                    models.ManyToManyField(
                        blank=True,
                        related_name='promociones',
                        to='producto.producto',
                    ),
                ),
            ],
            options={
                'db_table': 'promocion',
                'ordering': ['-created_at'],
            },
        ),
    ]
