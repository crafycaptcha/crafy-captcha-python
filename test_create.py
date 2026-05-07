from crafy_captcha import CrafyCAPTCHA

def test_crafy_captcha():
    print("🚀 Iniciando prueba de CrafyCAPTCHA en Python...\n")

    # 1. Inicializar la clase con llaves ficticias
    public_key = 'pk_e8972ec334767ff5d5754ed4c68a5887'
    secret_key = 'sk_aa9a0204a5beb09c228fa2e51b7bdcd064abd72e5e047e9914a5e2620aad2900'
    
    try:
        # Por defecto usará el directorio temporal del sistema operativo
        captcha = CrafyCAPTCHA(public_key, secret_key)
        
        # 2. Probar la creación de un flujo (create_flow)
        print("⏳ Generando opciones de flow...")
        opciones_personalizadas = {}
        
        # Esto prueba la generación de Nonces y la encriptación con PyNaCl/Cryptography
        flow_options = captcha.create_flow(opciones_personalizadas)
        
        print("✅ Flow encriptado generado exitosamente:")
        print(flow_options)

    except Exception as e:
        print("\n❌ Hubo un error durante la prueba:")
        print(str(e))

if __name__ == "__main__":
    test_crafy_captcha()