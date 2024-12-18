# IPT_Filter

### Выполнение .../books
![image](https://github.com/user-attachments/assets/46fa355c-e17e-4519-a612-6cc86779a3d9)

### Выполнение .../books?limit=1
![image](https://github.com/user-attachments/assets/1ef58178-6341-4f55-8963-c7a14733a3dd)

### Выполнение .../books?limit=1&page=2
![image](https://github.com/user-attachments/assets/81078026-684b-47c0-b7f8-21f8ec456234)

### Выполнение .../books?limit=2&sort=title
![image](https://github.com/user-attachments/assets/4270810a-cabd-411f-b03e-8c53889a1c2d)

### Выполнение .../books?limit=2&sort=title&order=desc
![image](https://github.com/user-attachments/assets/59ccb5e4-7ef5-4f7e-b420-f5220cff8926)

### Выполнение .../books?title=1984
![image](https://github.com/user-attachments/assets/7ed16c0e-b75c-42b3-95d2-12e504d40283)

``` go

package main

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Username string
	Password string
	Role     string
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
	Role string `json:"role"`
}

func generateToken(username string, role string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role, // Включаем роль в токен
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func login(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		return
	}

	// Проверяем имя пользователя и пароль
	storedPassword, ok := users[creds.Username]
	if !ok || storedPassword != creds.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	// Извлекаем роль пользователя из мапы roles
	role, roleExists := roles[creds.Username]
	if !roleExists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "role not assigned"})
		return
	}

	// Генерация токена с ролью пользователя
	token, err := generateToken(creds.Username, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "could not create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid token"})
				c.Abort() // Прерываем обработку запроса
				return
			}

			// Обработка истёкшего токена
			if ve, ok := err.(*jwt.ValidationError); ok && ve.Errors == jwt.ValidationErrorExpired {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "token expired"})
				c.Abort()
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}

		c.Next() // Если всё в порядке, передаём управление следующему обработчику
	}
}

var users = map[string]string{
	"admin":    "admin123",
	"user":     "password",
	"elektrik": "2003",
}

func register(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		return
	}

	// Проверка, существует ли пользователь
	if _, exists := users[creds.Username]; exists {
		c.JSON(http.StatusConflict, gin.H{"message": "user already exists"})
		return
	}

	// По умолчанию роль "user", можно добавить проверку или параметр для роли
	role := "user" // Устанавливаем роль по умолчанию как "user"

	// Можно добавить параметр для роли в запросе регистрации, например:
	if creds.Role != "" {
		role = creds.Role
	}

	// Регистрируем пользователя
	users[creds.Username] = creds.Password
	roles[creds.Username] = role // Сохраняем роль в мапе

	c.JSON(http.StatusCreated, gin.H{"message": "user registered successfully"})
}

var roles = map[string]string{
	"admin":    "admin",
	"user":     "user",
	"elektrik": "user",
}

func roleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}

		// Проверяем роль пользователя
		if claims.Role != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func refresh(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	claims := &Claims{}

	// Парсим исходный токен
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	// Проверяем, не истек ли срок действия токена
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		c.JSON(http.StatusBadRequest, gin.H{"message": "token not expired enough"})
		return
	}

	// Генерация нового токена с теми же данными (пользователь и роль), но с новым временем истечения
	newToken, err := generateToken(claims.Username, claims.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "could not create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": newToken})
}

var db *gorm.DB

func initDB() {
	dsn := "host=213.171.10.112 user=postgres password=67 dbname=bookdb port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	db.AutoMigrate(&Book{})
}

type Book struct {
	ID     uint   `gorm:"primaryKey" json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

func handleError(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, gin.H{"error": message})
}

func main() {
	initDB()
	router := gin.Default()

	router.POST("/login", login)
	router.POST("/register", register)
	router.POST("/refresh", refresh)

	protected := router.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/books", getBooks)

		protected.GET("/products/:id", getBookByID)

		protected.POST("/books", roleMiddleware("admin"), createBook)

		protected.PUT("/books/:id", roleMiddleware("admin"), updateBook)

		protected.DELETE("/books/:id", roleMiddleware("admin"), deleteBook)

	}
	router.Run(":8080")
}

func getBooks(c *gin.Context) {
	var books []Book
	var total int64

	// Получаем параметры фильтров, сортировки и пагинации
	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "10")
	sort := c.DefaultQuery("sort", "id")
	order := c.DefaultQuery("order", "asc")
	title := c.Query("title")

	// Преобразуем строковые параметры в int
	pageInt, _ := strconv.Atoi(page)
	limitInt, _ := strconv.Atoi(limit)
	offset := (pageInt - 1) * limitInt

	query := db.Model(&Book{})

	// Применяем фильтры
	if title != "" {
		query = query.Where("title ILIKE ?", "%"+title+"%")
	}

	query.Count(&total)

	// Применяем сортировку
	if order != "asc" && order != "desc" {
		order = "asc" // По умолчанию ascending
	}
	query = query.Order(sort + " " + order).Limit(limitInt).Offset(offset)

	// Загружаем продукты и считаем общее количество
	query.Find(&books)

	// Возращаем результат
	c.JSON(http.StatusOK, gin.H{
		"data":  books,
		"total": total,
		"page":  pageInt,
		"limit": limitInt,
	})
}

func getBookByID(c *gin.Context) {
	id := c.Param("id")
	var book Book
	if err := db.First(&book, id).Error; err != nil {
		handleError(c, http.StatusNotFound, "Book not found")
		return
	}
	c.JSON(http.StatusOK, book)

}

func createBook(c *gin.Context) {
	var newBook Book

	if err := c.BindJSON(&newBook); err != nil {
		handleError(c, http.StatusBadRequest, "Invalid request")
		return
	}

	db.Create(&newBook)
	c.JSON(http.StatusCreated, newBook)

}

func updateBook(c *gin.Context) {
	id := c.Param("id")
	var updatedBook Book

	if err := c.BindJSON(&updatedBook); err != nil {
		handleError(c, http.StatusBadRequest, "Invalid request")
		return
	}

	if err := db.Model(&Book{}).Where("id = ?", id).Updates(updatedBook).Error; err != nil {
		handleError(c, http.StatusNotFound, "Book not found")
		return
	}

	c.JSON(http.StatusOK, updatedBook)
}

func deleteBook(c *gin.Context) {
	id := c.Param("id")

	if err := db.Delete(&Book{}, id).Error; err != nil {
		handleError(c, http.StatusNotFound, "Book not found")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Book deleted"})

}

func getBooksWithTimeout(c *gin.Context) {
	// Создаем контекст с тайм-аутом 2 секунды
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	var books []Book
	var total int64

	// Получаем параметры фильтров, сортировки и пагинации
	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "10")
	sort := c.DefaultQuery("sort", "id")
	order := c.DefaultQuery("order", "asc")
	title := c.Query("title")

	// Преобразуем строковые параметры в int
	pageInt, _ := strconv.Atoi(page)
	limitInt, _ := strconv.Atoi(limit)
	offset := (pageInt - 1) * limitInt

	query := db.Model(&Book{})

	// Применяем фильтры
	if title != "" {
		query = query.Where("name ILIKE ?", "%"+title+"%")
	}

	query.Count(&total)

	// Применяем сортировку
	if order != "asc" && order != "desc" {
		order = "asc" // По умолчанию ascending
	}
	query = query.Order(sort + " " + order).Limit(limitInt).Offset(offset)

	// Загружаем продукты с использованием контекста
	if err := query.WithContext(ctx).Find(&books).Error; err != nil {
		if err == context.DeadlineExceeded {
			handleError(c, http.StatusRequestTimeout, "Request timed out")
		} else {
			handleError(c, http.StatusInternalServerError, "Failed to fetch books")
		}
		return
	}

	// Возвращаем результат
	c.JSON(http.StatusOK, gin.H{
		"data":  books,
		"total": total,
		"page":  pageInt,
		"limit": limitInt,
	})
}


```
