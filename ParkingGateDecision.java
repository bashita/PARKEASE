import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;

public class ParkingGateDecision {
    public enum VehicleType {
        TWO_WHEELER,
        FOUR_WHEELER,
        TRUCK
    }

    public enum SlotType {
        NORMAL,
        DISABLED
    }

    public static final class Decision {
        private final boolean allowed;
        private final String message;
        private final BigDecimal price;

        public Decision(boolean allowed, String message, BigDecimal price) {
            this.allowed = allowed;
            this.message = message;
            this.price = price;
        }

        public boolean isAllowed() {
            return allowed;
        }

        public String getMessage() {
            return message;
        }

        public BigDecimal getPrice() {
            return price;
        }
    }

    private static final Map<VehicleType, BigDecimal> VEHICLE_RATES = Map.of(
            VehicleType.TWO_WHEELER, new BigDecimal("35"),
            VehicleType.FOUR_WHEELER, new BigDecimal("60"),
            VehicleType.TRUCK, new BigDecimal("120")
    );

    public static Decision evaluateParkingGate(VehicleType vehicleType, SlotType slotType, String slotVehicleType, boolean supportsBigVehicles, String startTime, String endTime) {
        if (vehicleType == null) {
            return new Decision(false, "Choose a valid vehicle type.", BigDecimal.ZERO);
        }

        if (slotType == null) {
            return new Decision(false, "Choose a valid parking slot type.", BigDecimal.ZERO);
        }

        if (startTime == null || endTime == null || startTime.isBlank() || endTime.isBlank()) {
            return new Decision(false, "Choose a valid parking time period before confirming the gate check.", BigDecimal.ZERO);
        }

        LocalTime start;
        LocalTime end;
        try {
            start = LocalTime.parse(startTime);
            end = LocalTime.parse(endTime);
        } catch (Exception e) {
            return new Decision(false, "Choose a valid parking time period before confirming the gate check.", BigDecimal.ZERO);
        }

        long durationHours = ChronoUnit.HOURS.between(start, end);
        if (durationHours <= 0) {
            return new Decision(false, "Choose a valid parking time period before confirming the gate check.", BigDecimal.ZERO);
        }

        if (slotType == SlotType.DISABLED) {
            if (vehicleType == VehicleType.TWO_WHEELER) {
                return new Decision(false, "Two-wheelers cannot use disabled parking slots.", BigDecimal.ZERO);
            }
            if (vehicleType == VehicleType.TRUCK) {
                return new Decision(false, "Large vehicles are not allowed in disabled spaces.", BigDecimal.ZERO);
            }
        }

        if (slotVehicleType != null && !"all".equalsIgnoreCase(slotVehicleType)) {
            VehicleType allowedVehicleType = parseVehicleType(slotVehicleType);
            if (allowedVehicleType == null) {
                return new Decision(false, "This slot is configured with an invalid vehicle type.", BigDecimal.ZERO);
            }

            if (vehicleType == VehicleType.TRUCK && allowedVehicleType != VehicleType.TRUCK && !supportsBigVehicles) {
                return new Decision(false, "This parking slot is meant for " + allowedVehicleType.name().toLowerCase().replace("_", " ") + " vehicles only.", BigDecimal.ZERO);
            }

            if (vehicleType != VehicleType.TRUCK && vehicleType != allowedVehicleType) {
                return new Decision(false, "This parking slot is meant for " + allowedVehicleType.name().toLowerCase().replace("_", " ") + " vehicles only.", BigDecimal.ZERO);
            }
        }

        if (supportsBigVehicles && vehicleType == VehicleType.TWO_WHEELER) {
            return new Decision(false, "This parking slot is reserved for large vehicles.", BigDecimal.ZERO);
        }

        if (vehicleType == VehicleType.TRUCK && !supportsBigVehicles) {
            return new Decision(false, "This space is not large enough for a truck or big vehicle.", BigDecimal.ZERO);
        }

        if (vehicleType == VehicleType.TRUCK && slotType == SlotType.NORMAL && !supportsBigVehicles) {
            return new Decision(false, "A truck is too large for a standard compact slot. Please choose a larger bay or a smaller vehicle.", BigDecimal.ZERO);
        }

        BigDecimal hourlyRate = VEHICLE_RATES.get(vehicleType);
        if (hourlyRate == null) {
            return new Decision(false, "Choose a valid vehicle type.", BigDecimal.ZERO);
        }

        BigDecimal price = hourlyRate.multiply(BigDecimal.valueOf(durationHours)).setScale(2, RoundingMode.HALF_UP);
        return new Decision(
                true,
                "Gate check passed. This slot matches your vehicle and the parking duration.",
                price
        );
    }

    public static Decision evaluateParkingGate(VehicleType vehicleType, SlotType slotType, String startTime, String endTime) {
        return evaluateParkingGate(vehicleType, slotType, "all", false, startTime, endTime);
    }

    private static VehicleType parseVehicleType(String value) {
        if (value == null) return null;
        switch (value.trim().toLowerCase()) {
            case "two_wheeler": return VehicleType.TWO_WHEELER;
            case "four_wheeler": return VehicleType.FOUR_WHEELER;
            case "truck": return VehicleType.TRUCK;
            default: return null;
        }
    }

    private static SlotType parseSlotType(String value) {
        if (value == null) return null;
        switch (value.trim().toLowerCase()) {
            case "normal": return SlotType.NORMAL;
            case "disabled": return SlotType.DISABLED;
            default: return null;
        }
    }

    private static String toJson(Decision decision) {
        return String.format(
                "{\"allowed\":%s,\"message\":\"%s\",\"price\":\"%s\"}",
                decision.isAllowed(),
                decision.getMessage().replace("\"", "\\\"") ,
                decision.getPrice().setScale(2, RoundingMode.HALF_UP)
        );
    }

    public static void main(String[] args) {
        if (args.length == 6) {
            VehicleType vehicleType = parseVehicleType(args[0]);
            SlotType slotType = parseSlotType(args[1]);
            String slotVehicleType = args[2];
            boolean supportsBigVehicles = Boolean.parseBoolean(args[3]);
            Decision decision = evaluateParkingGate(vehicleType, slotType, slotVehicleType, supportsBigVehicles, args[4], args[5]);
            System.out.println(toJson(decision));
            return;
        }

        if (args.length == 4) {
            VehicleType vehicleType = parseVehicleType(args[0]);
            SlotType slotType = parseSlotType(args[1]);
            Decision decision = evaluateParkingGate(vehicleType, slotType, args[2], args[3]);
            System.out.println(toJson(decision));
            return;
        }

        Decision approved = evaluateParkingGate(VehicleType.FOUR_WHEELER, SlotType.NORMAL, "09:00", "12:00");
        System.out.println("APPROVED: " + approved.isAllowed() + " | " + approved.getMessage() + " | Price: ₹" + approved.getPrice());

        Decision rejected = evaluateParkingGate(VehicleType.TWO_WHEELER, SlotType.DISABLED, "09:00", "12:00");
        System.out.println("REJECTED: " + rejected.isAllowed() + " | " + rejected.getMessage() + " | Price: ₹" + rejected.getPrice());

        Decision truckBlocked = evaluateParkingGate(VehicleType.TRUCK, SlotType.NORMAL, "09:00", "12:00");
        System.out.println("TRUCK BLOCKED: " + truckBlocked.isAllowed() + " | " + truckBlocked.getMessage() + " | Price: ₹" + truckBlocked.getPrice());
    }
}
