/**
 * lib/errors.js — Manejo de errores sin oráculo.
 *
 * Corrige MIRAGE-008 (errores distinguibles = oráculo de parsing).
 *
 * Problema original: `deserializePayload` y el parser del envelope emitían 4+
 * mensajes distintos ("filename length inválido", "file size inválido", ...) y
 * el servidor los devolvía tal cual al cliente junto al array `steps`, que
 * además trazaba la ruta interna de ejecución (si se usó hardware lock, si se
 * disparó duress, qué modo se parseó). Eso es un oráculo: la misma clase de
 * fuga que hizo explotables los ataques de Padding Oracle.
 *
 * Solución: dos clases de error.
 *   - OpaqueError: todo fallo posterior a (o relacionado con) la autenticación
 *     colapsa a UN ÚNICO mensaje público constante. El detalle real viaja en
 *     `.internal` y solo se escribe en el log local.
 *   - PolicyError: errores previos a cualquier operación criptográfica y que no
 *     dependen del contenido del archivo (p. ej. "la contraseña debe tener 12
 *     caracteres"). Estos SÍ pueden ser específicos porque no revelan nada
 *     sobre el ciphertext: el usuario ya conoce su propia entrada.
 */

/** Mensaje público único para cualquier fallo criptográfico o de parsing. */
export const OPAQUE_MESSAGE =
  'Authentication failed or archive is corrupted / not a valid Mirage archive.';

/**
 * Error cuyo mensaje público es constante.
 * @param {string} internal Detalle técnico real (solo para logs locales).
 */
export class OpaqueError extends Error {
  constructor(internal) {
    super(OPAQUE_MESSAGE);
    this.name = 'OpaqueError';
    this.internal = internal;
    this.isOpaque = true;
  }
}

/**
 * Error de política/validación de entrada del usuario.
 * Seguro de exponer: no depende del contenido del archivo cifrado.
 */
export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
    this.isPolicy = true;
  }
}

/**
 * Convierte cualquier excepción en un par { publicMessage, internalMessage }.
 * Por defecto se asume opaco: un error inesperado nunca debe filtrar detalle.
 */
export function toPublicError(err) {
  if (err && err.isPolicy) {
    return {
      publicMessage: err.message,
      internalMessage: err.message,
      message: err.message,
      internal: err.message,
      status: 400
    };
  }
  if (err && err.isOpaque) {
    return {
      publicMessage: OPAQUE_MESSAGE,
      internalMessage: err.internal || err.message,
      message: OPAQUE_MESSAGE,
      internal: err.internal || err.message,
      status: 401
    };
  }
  return {
    publicMessage: OPAQUE_MESSAGE,
    internalMessage: err && err.message ? err.message : String(err),
    message: OPAQUE_MESSAGE,
    internal: err && err.message ? err.message : String(err),
    status: 401
  };
}

/**
 * Filtra los pasos de progreso para no exponer la ruta interna de ejecución
 * cuando la operación falla (MIRAGE-008 K3).
 *
 * En éxito los pasos son informativos y útiles para el usuario. En fallo se
 * suprimen por completo: son precisamente los que revelan cuántos intentos de
 * derivación se hicieron, si el hardware lock aplicó o si se probó el bloque
 * decoy.
 */
export function sanitizeSteps(steps, success) {
  if (success) return steps;
  return [];
}
