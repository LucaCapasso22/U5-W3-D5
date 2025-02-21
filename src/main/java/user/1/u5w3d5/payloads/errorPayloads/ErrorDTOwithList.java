package user.1.u5w3d5.payloads.errorPayloads;

import java.time.LocalDateTime;
import java.util.List;

public record ErrorDTOwithList(
        String message,
        LocalDateTime timestamp,
        List<String> errorsList
) {
}
