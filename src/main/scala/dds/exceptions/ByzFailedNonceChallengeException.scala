package dds.exceptions


class ByzFailedNonceChallengeException(message: String = null, cause: Throwable = null) extends
  RuntimeException(ByzFailedNonceChallengeException.defaultMessage(message, cause), cause)

object ByzFailedNonceChallengeException {
  def defaultMessage(message: String, cause: Throwable) =
    if (message != null) message
    else if (cause != null) cause.toString()
    else null
}
