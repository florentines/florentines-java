package io.florentine;

import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public abstract class CommittingDEM {

    private final String identifier;

    CommittingDEM(String identifier) {
        this.identifier = requireNonNull(identifier);
    }

    public final String getIdentifier() {
        return identifier;
    }

    abstract KeyAndTag encapsulate(DataKey key, List<byte[]> publicData, List<byte[]> secretData);
    abstract Optional<DataKey> decapsulate(DataKey key, List<byte[]> publicData, List<byte[]> secretData, byte[] tag);

    public record KeyAndTag(DataKey key, byte[] tag) {}
}
