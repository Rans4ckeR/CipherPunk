namespace RS.Schannel.Manager.UI;

using System.Text;

public static class ExceptionMessageBuilder
{
    public static string GetDetailedExceptionInfo(this Exception ex)
    {
        return new StringBuilder().GetExceptionInfo(ex).ToString();
    }

    private static StringBuilder GetExceptionInfo(this StringBuilder sb, Exception ex)
    {
        sb.AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.GetType)}: {ex.GetType()}"))
            .AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.Message)}: {ex.Message}"))
            .GetExceptionDetails(ex);

        if (ex is AggregateException aggregateException)
        {
            foreach (Exception innerException in aggregateException.InnerExceptions)
            {
                _ = sb.AppendLine(FormattableString.Invariant($"{nameof(AggregateException)}.{nameof(AggregateException.InnerExceptions)}:"))
                    .GetExceptionInfo(innerException);
            }
        }
        else if (ex.InnerException is not null)
        {
            _ = sb.AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.InnerException)}:"))
                .GetExceptionInfo(ex.InnerException);
        }

        return sb;
    }

    private static void GetExceptionDetails(this StringBuilder sb, Exception ex)
    {
        _ = sb.AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.Source)}: {ex.Source}"))
            .AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.TargetSite)}: {ex.TargetSite}"));

        _ = sb.AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.StackTrace)}: {ex.StackTrace}"));
    }
}