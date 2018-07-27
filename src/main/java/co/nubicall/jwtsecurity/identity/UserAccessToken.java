package co.nubicall.jwtsecurity.identity;


public class UserAccessToken {

    private String username;

    private String accessToken;

    private long expiresIn;

    public UserAccessToken() {
        super();
    }

    public UserAccessToken(String username, String accessToken, long expiresIn) {
        super();
        this.username = username;
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

}