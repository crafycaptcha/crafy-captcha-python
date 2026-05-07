from crafy_captcha import CrafyCAPTCHA

def test_crafy_captcha():
    print("🚀 Iniciando prueba de CrafyCAPTCHA en Python...\n")

    # 1. Inicializar la clase con llaves ficticias
    public_key = 'pk_e8972ec334767ff5d5754ed4c68a5887'
    secret_key = 'sk_aa9a0204a5beb09c228fa2e51b7bdcd064abd72e5e047e9914a5e2620aad2900'
    
    try:
        # Por defecto usará el directorio temporal del sistema operativo
        captcha = CrafyCAPTCHA(public_key, secret_key, 'http://localhost/proyectos/CrafyCAPTCHA/api')
        
        # 2. Probar la creación de un flujo (create_flow)
        print("⏳ Generando opciones de flow...")
        opciones_personalizadas = {
            'theme': 'dark',
            'user_id': 99
        }
        
        # Esto prueba la generación de Nonces y la encriptación con PyNaCl/Cryptography
        flow_options = captcha.create_flow(opciones_personalizadas)
        
        print("✅ Flow encriptado generado exitosamente:")
        print(flow_options)
        print("\n-----------------------------------\n")

        # Esto prueba la generación de Nonces y la encriptación con PyNaCl/Cryptography
        public_token = captcha.get_public_token()
        
        print("✅ Token público generado exitosamente:")
        print(public_token)
        print("\n-----------------------------------\n")

        # 3. Limpiar los nonces temporales creados para no ensuciar el disco
        borrados = captcha.clear_all_nonces()
        print(f"✅ Limpieza completada: Se borraron {borrados} archivos temporales (nonces).")

        print("\n🎉 ¡Tu SDK de Python funciona perfectamente!")

    except Exception as e:
        print("\n❌ Hubo un error durante la prueba:")
        print(str(e))

if __name__ == "__main__":
    test_crafy_captcha()