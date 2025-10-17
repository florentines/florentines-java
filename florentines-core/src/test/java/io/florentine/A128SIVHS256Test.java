package io.florentine;

import org.assertj.core.api.Condition;
import org.testng.annotations.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.function.Predicate.not;
import static org.assertj.core.api.Assertions.assertThat;

public class A128SIVHS256Test {

    @Test
    public void shouldRoundtrip() {
        // given
        var dem = A128SIV_HS256.INSTANCE;
        var key = new DataKey(new byte[16], "A128SIV-HS256");
        var pub = List.of("Some Assoc Data".getBytes(UTF_8));
        var sec = List.of("Foo".getBytes(UTF_8), "Bar".getBytes(UTF_8));

        // when
        var encaps = dem.encapsulate(key, pub, sec);
        var result = dem.decapsulate(key, pub, sec, encaps.tag());

        // then
        assertThat(result).isPresent()
                .hasValueSatisfying(new Condition<>(not(DataKey::isDestroyed), "not destroyed"))
                .hasValue(encaps.key());
    }
}