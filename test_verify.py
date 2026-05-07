from crafy_captcha import CrafyCAPTCHA

def probar_verificacion():
    print("🛡️ === CrafyCAPTCHA Verify Tester === 🛡️\n")

    # Asegúrate de usar las mismas llaves con las que se generó el payload
    public_key = 'pk_e8972ec334767ff5d5754ed4c68a5887'
    secret_key = 'sk_aa9a0204a5beb09c228fa2e51b7bdcd064abd72e5e047e9914a5e2620aad2900'

    try:
        captcha = CrafyCAPTCHA(public_key, secret_key)
        
        print("Pega el token/payload (la cadena larga en base64) que devuelve el frontend.")
        payload = input("> ")

        payload = payload.strip()
        if not payload:
            print("\n⚠️ No ingresaste ningún payload.")
            return

        print("\n⏳ Verificando integridad, firma y caducidad...")
        
        # Llamamos al método de verificación
        es_valido = captcha.verify_flow(payload)

        if es_valido:
            print("\n✅ ¡ÉXITO! El token es VÁLIDO.")
            print("El desafío fue resuelto correctamente y el nonce ha sido consumido.")
        else:
            # Si falla, obtenemos el motivo exacto
            motivo_error = captcha.get_last_flow_verify_error()
            print(f"\n❌ TOKEN INVÁLIDO.")
            print(f"Motivo: {motivo_error}")

    except Exception as e:
        print(f"\n❌ Ocurrió un error inesperado en el script:")
        print(str(e))

if __name__ == "__main__":
    probar_verificacion()