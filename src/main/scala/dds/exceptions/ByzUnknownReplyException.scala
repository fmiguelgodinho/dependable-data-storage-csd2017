package dds.exceptions


class ByzUnknownReplyException(message: String = null, cause: Throwable = null) extends
  RuntimeException(ByzUnknownReplyException.defaultMessage(message, cause), cause)

object ByzUnknownReplyException {
  def defaultMessage(message: String, cause: Throwable) =
    if (message != null) message
    else if (cause != null) cause.toString()
    else null
}
