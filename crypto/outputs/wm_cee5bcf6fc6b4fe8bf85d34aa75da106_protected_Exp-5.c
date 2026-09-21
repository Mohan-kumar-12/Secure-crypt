/* =========================================
 * Digital Content Protection & Authenticity
 * Owner: Mohan Kumar J
 * Project ID: PROJECT-001
 * Watermark ID: WM-CODE-2026-0C1B05E4
 * Created: 2026-08-14T15:17:08.360292+00:00
 * ========================================= */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
int main()
{
    char text[100];
    int a, b, i;
    printf("Enter Plain Text (Only Letters): ");
    scanf("%s", text);
    printf("Enter value of a: ");
    scanf("%d", &a);
    printf("Enter value of b: ");
    scanf("%d", &b);
    printf("\nCipher Text: ");
    for(i = 0; text[i] != '\0'; i++)
    {
        char ch = text[i];
        if(isupper(ch))
        {
            ch = ((a * (ch - 'A') + b) % 26) + 'A';
        }
        else if(islower(ch))
        {
            ch = ((a * (ch - 'a') + b) % 26) + 'a';
        }
        printf("%c", ch);
    }
    printf("\n");
    return 0;
}