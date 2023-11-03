# Ataque De Fuerza Bruta Para Archivos .ZIP

Este script está diseñado para llevar a cabo un ataque de fuerza bruta en un archivo ZIP protegido con contraseña, utilizando un diccionario de contraseñas. Este script podría beneficiar a las personas en situaciones donde necesitan recuperar el acceso a un archivo ZIP protegido del cual han olvidado la contraseña. También podría ser útil en pruebas de penetración ética para probar la seguridad de archivos ZIP protegidos con contraseñas débiles. Sin embargo, es importante destacar que el uso de fuerza bruta para acceder a archivos sin permiso puede ser ilegal y debe realizarse con permiso explícito o en situaciones legales y éticas.


<img align="center" height="480" width="1000" alt="GIF" src="https://github.com/Yextep/Keyex/assets/114537444/7f7b7bad-9302-4f85-af81-f83504ea9a18"/>

# Función main

Esta función es el punto de entrada del script. Solicita al usuario la ruta del archivo ZIP protegido y la ruta del archivo de diccionario. Luego, intenta abrir el archivo de diccionario y leer las contraseñas que contiene. Si el archivo de diccionario no existe, muestra un mensaje de error y finaliza. Luego, llama a la función ataque_fuerza_bruta con las rutas del archivo ZIP y el diccionario.

# Función ataque_fuerza_bruta 

Esta función toma dos argumentos, el primero es la ruta de un archivo ZIP protegido con contraseña, y el segundo es la ruta a un archivo de diccionario (un archivo de texto con una lista de posibles contraseñas). La función intenta descomprimir el archivo ZIP utilizando contraseñas del diccionario, una por una, hasta que se encuentra una contraseña válida o se agota la lista. Si se encuentra una contraseña, la muestra en la consola y termina. Si no se encuentra ninguna contraseña válida, muestra un mensaje indicando que la contraseña no se encontró.

# Instalación

Clonamos el repositorio
```bash
git clone https://github.com/Yextep/BruteZip
```
Accedemos a la carpeta
```bash
cd BruteZip
```
Instalamos requerimientos
```bash
pip install -r requeriments.txt
```
Ejecutamos el Script
```bash
python3 brute-zip.py
```
