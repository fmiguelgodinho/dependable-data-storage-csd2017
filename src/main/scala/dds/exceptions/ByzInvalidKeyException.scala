package dds.exceptions


class ByzInvalidKeyException(message: String = null, cause: Throwable = null) extends
  RuntimeException(ByzInvalidKeyException.defaultMessage(message, cause), cause)

object ByzInvalidKeyException {
  def defaultMessage(message: String, cause: Throwable) =
    if (message != null) message
    else if (cause != null) cause.toString()
    else null
}
