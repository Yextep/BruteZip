import pyzipper
import sys

def ataque_fuerza_bruta(archivo, diccionario, length_based=False, longitud=None):
    with pyzipper.AESZipFile(archivo) as zip_ref:
        total_passwords = len(diccionario)
        for index, password in enumerate(diccionario):
            if length_based and len(password) != longitud:
                continue
            try:
                zip_ref.extractall(pwd=password.encode('utf-8'))
                print(f'\nContraseña encontrada: {password}')
                return
            except Exception as e:
                pass
            # Calcula el progreso y muestra la barra de caracteres '*' en la misma línea
            progress = (index + 1) / total_passwords
            sys.stdout.write('\r[' + '*' * int(progress * 50) + ' ' * (50 - int(progress * 50)) + f'] {int(progress * 100)}%')
            sys.stdout.flush()

    print('\nContraseña no encontrada')

def main():
    archivo = input('Introduce la ruta del archivo protegido: ')
    diccionario = input('Introduce la ruta del diccionario .txt: ')
    longitud = None
    length_based = input('¿Deseas realizar un ataque de fuerza bruta por longitud? (S/N): ')
    if length_based.lower() == 's':
        longitud = int(input('Introduce la longitud de contraseña a probar: '))

    try:
        with open(diccionario, 'r', encoding='utf-8', errors='replace') as f:
            diccionario = f.read().splitlines()
    except FileNotFoundError:
        print('El diccionario no existe')
        return

    ataque_fuerza_bruta(archivo, diccionario, length_based=True, longitud=longitud)

if __name__ == '__main__':
    main()
