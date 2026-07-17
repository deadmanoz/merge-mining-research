s|EVP_CIPHER_CTX ctx;|EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();|g
s|EVP_CIPHER_CTX_init(&ctx);|if (!ctx) return false;|g
s|EVP_EncryptInit_ex(&ctx,|EVP_EncryptInit_ex(ctx,|g
s|EVP_EncryptUpdate(&ctx,|EVP_EncryptUpdate(ctx,|g
s|EVP_EncryptFinal_ex(&ctx,|EVP_EncryptFinal_ex(ctx,|g
s|EVP_DecryptInit_ex(&ctx,|EVP_DecryptInit_ex(ctx,|g
s|EVP_DecryptUpdate(&ctx,|EVP_DecryptUpdate(ctx,|g
s|EVP_DecryptFinal_ex(&ctx,|EVP_DecryptFinal_ex(ctx,|g
s|EVP_CIPHER_CTX_cleanup(&ctx);|EVP_CIPHER_CTX_free(ctx);|g
