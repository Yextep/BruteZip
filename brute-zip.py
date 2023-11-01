import pyzipper

def ataque_fuerza_bruta(archivo, diccionario):
    with pyzipper.AESZipFile(archivo) as zip_ref:
        for password in diccionario:
            try:
                zip_ref.extractall(pwd=password.encode('utf-8'))
                print(f'Contraseña encontrada: {password}')
                return
            except Exception as e:
                pass

    print('Contraseña no encontrada')

def main():
    archivo = input('Introduce la ruta del archivo protegido: ')
    diccionario = input('Introduce la ruta del diccionario .txt: ')

    try:
        with open(diccionario, 'r', encoding='utf-8', errors='replace') as f:
            diccionario = f.read().splitlines()
    except FileNotFoundError:
        print('El diccionario no existe')
        return

    ataque_fuerza_bruta(archivo, diccionario)

if __name__ == '__main__':
    main()
