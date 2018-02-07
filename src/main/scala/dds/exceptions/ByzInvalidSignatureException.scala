package dds.exceptions


class ByzInvalidSignatureException(message: String = null, cause: Throwable = null) extends
  RuntimeException(ByzInvalidSignatureException.defaultMessage(message, cause), cause)

object ByzInvalidSignatureException {
  def defaultMessage(message: String, cause: Throwable) =
    if (message != null) message
    else if (cause != null) cause.toString()
    else null
}
